#![no_std]

mod net;
mod addr;
mod consts;
pub mod packets;
pub mod results;
pub(crate) mod utils;

#[macro_use]
extern crate alloc;

pub use addr::IPv4;
pub use addr::MacAddress;
use alloc::boxed::Box;
use net::Arp;
use net::Eth;
use net::Ip;
use net::UDP;
use packets::arp::ArpPacket;
use packets::arp::ArpType;
use results::Packet;
use utils::UnsafeRefIter;
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
        let mut data_ptr_iter = UnsafeRefIter::new(data);
        let eth_header = unsafe{data_ptr_iter.next::<Eth>()}.unwrap();
        match eth_header.rtype.to_be() {
            ETH_RTYPE_IP => {
                let ip_header = unsafe{data_ptr_iter.next::<Ip>()}.unwrap();
                match ip_header.pro {
                    IP_PROTOCAL_UDP => {
                        let udp_header = unsafe{data_ptr_iter.next::<UDP>()}.unwrap();
                        let data = unsafe{data_ptr_iter.get_curr_arr()};
                        let len = data.len();
                        Packet::UDP(packets::udp::UDPPacket { 
                            source_ip: IPv4::from_u32(ip_header.src.to_be()), 
                            source_mac: MacAddress::new(eth_header.shost), 
                            source_port: udp_header.sport.to_be(), 
                            dest_ip: IPv4::from_u32(ip_header.dst.to_be()), 
                            dest_mac: MacAddress::new(eth_header.dhost), 
                            dest_port: udp_header.dport.to_be(), 
                            data_len: len, 
                            data: data
                        })
                    }
                    _ => {
                        Packet::None
                    }
                }
            },
            ETH_RTYPE_ARP => {
                let arp_header = unsafe{data_ptr_iter.next::<Arp>()}.unwrap();
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