#![no_std]

mod net;
mod addr;
mod eth;
mod consts;
pub mod packets;
pub mod results;

#[macro_use]
extern crate alloc;

pub use addr::IPv4;
pub use addr::MacAddress;
use alloc::boxed::Box;
use net::Arp;
use net::Ip;
use net::UDP;
use packets::arp::ArpPacket;
use packets::arp::ArpType;
use results::Packet;
use core::marker::PhantomData;
use core::mem::size_of;
use core::slice;
use consts::*;



pub struct LoseStack {
    pub ip:  IPv4,
    pub mac: MacAddress
}

impl LoseStack {
    pub fn new(ip: IPv4, mac: MacAddress) -> Self {
        Self {
            ip,
            mac
        }
    }

    pub fn analysis(&self, data: &[u8]) -> Packet {
        let eth_header = unsafe{(data.as_ptr() as usize as *const eth::Eth).as_ref()}.unwrap();
        match eth_header.rtype.to_be() {
            ETH_RTYPE_IP => {
                let ip_header = unsafe{((data.as_ptr() as usize + size_of::<eth::Eth>()) as *const Ip).as_ref()}.unwrap();

                match ip_header.pro {
                    IP_PROTOCAL_UDP => {
                        let ptr = data.as_ptr() as usize + size_of::<eth::Eth>() + size_of::<Ip>();
                        let udp_header = unsafe{(ptr as *const UDP).as_ref()}.unwrap();
                        let len = udp_header.ulen.to_be() as usize - size_of::<UDP>();
                        let data = unsafe {
                            slice::from_raw_parts((ptr + size_of::<UDP>()) as *const u8, len)
                        };
                        Packet::UDP(packets::udp::UDPPacket { 
                            source_ip: IPv4::from_u32(ip_header.src.to_be()), 
                            source_mac: MacAddress::new(eth_header.shost), 
                            source_port: udp_header.sport.to_be(), 
                            dest_ip: IPv4::from_u32(ip_header.dst.to_be()), 
                            dest_mac: MacAddress::new(eth_header.dhost), 
                            dest_port: udp_header.dport.to_be(), 
                            data_len: len, 
                            data: Box::new(data)
                        })
                    }
                    _ => {
                        Packet::None
                    }
                }
            },
            ETH_RTYPE_ARP => {
                let arp_header = unsafe{((data.as_ptr() as usize + size_of::<eth::Eth>()) as *const Arp).as_ref()}.unwrap();

                if arp_header.hlen != 6 || arp_header.plen != 4 {
                    // Unsupported now
                    Packet::Todo("can't support the case that not ipv4")
                } else {
                    let rtype = ArpType::form_u16(arp_header.op.to_be());
                    Packet::ARP(ArpPacket::new(
                        IPv4::from_u32(arp_header.spa.to_be()), 
                        MacAddress::new(arp_header.sha), 
                        IPv4::from_u32(arp_header.tpa.to_be()), 
                        MacAddress::new(arp_header.tha), 
                        rtype
                    ))
                }
            },
            _ => Packet::None // Unsupported type
        }
    }
}