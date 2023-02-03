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

    fn analysis_udp(&self, mut data_ptr_iter: UnsafeRefIter, ip_header: &Ip, eth_header: &Eth) -> Packet {
        let udp_header = unsafe{data_ptr_iter.next::<UDP>()}.unwrap();
        let data = unsafe{data_ptr_iter.get_curr_arr()};
        let data_len = data.len();

        Packet::UDP(packets::udp::UDPPacket { 
            source_ip: IPv4::from_u32(ip_header.src.to_be()), 
            source_mac: MacAddress::new(eth_header.shost), 
            source_port: udp_header.sport.to_be(), 
            dest_ip: IPv4::from_u32(ip_header.dst.to_be()), 
            dest_mac: MacAddress::new(eth_header.dhost), 
            dest_port: udp_header.dport.to_be(), 
            data_len, 
            data
        })
    }

    fn analysis_ip(&self, mut data_ptr_iter: UnsafeRefIter, eth_header: &Eth) -> Packet {
        let ip_header = unsafe{data_ptr_iter.next::<Ip>()}.unwrap();

        if ip_header.vhl != IP_HEADER_VHL {
            return Packet::None
        }

        if ip_header.dst.to_be() != self.ip.to_u32() {
            return Packet::None
        }

        match ip_header.pro {
            IP_PROTOCAL_UDP => self.analysis_udp(data_ptr_iter, ip_header, eth_header),
            _ => Packet::None
        }
    }

    fn analysis_arp(&self, mut data_ptr_iter: UnsafeRefIter) -> Packet {
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
    }

    pub fn analysis(&self, data: &[u8]) -> Packet {
        let mut data_ptr_iter = UnsafeRefIter::new(data);
        let eth_header = unsafe{data_ptr_iter.next::<Eth>()}.unwrap();
        match eth_header.rtype.to_be() {
            ETH_RTYPE_IP => self.analysis_ip(data_ptr_iter, eth_header),
            ETH_RTYPE_ARP => self.analysis_arp(data_ptr_iter),
            _ => Packet::None // Unsupported type
        }
    }
}