use core::net::Ipv4Addr;

use alloc::vec::Vec;

use crate::consts::{
    EthRtype, ARP_ETHADDR_LEN, ARP_HRD_ETHER, ARP_OP_REPLY, ARP_OP_REQUEST, BROADCAST_MAC,
};
use crate::net::{Arp, Eth, ARP_LEN, ETH_LEN};
use crate::utils::UnsafeRefIter;
use crate::MacAddress;

#[derive(Debug, Clone, Copy)]
pub enum ArpType {
    Request,
    Reply,
    Unsupported,
}

impl ArpType {
    pub fn form_u16(rtype: u16) -> Self {
        match rtype {
            ARP_OP_REQUEST => ArpType::Request,
            ARP_OP_REPLY => ArpType::Reply,
            _ => ArpType::Unsupported,
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            ArpType::Request => 1,
            ArpType::Reply => 2,
            ArpType::Unsupported => 0,
        }
    }
}

#[derive(Debug)]
pub struct ArpPacket {
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddress,
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddress,
    pub rtype: ArpType,
}

impl ArpPacket {
    pub fn new(
        sender_ip: Ipv4Addr,
        sender_mac: MacAddress,
        target_ip: Ipv4Addr,
        target_mac: MacAddress,
        rtype: ArpType,
    ) -> Self {
        ArpPacket {
            sender_ip,
            sender_mac,
            target_ip,
            target_mac,
            rtype,
        }
    }

    pub fn build_data(&self) -> Vec<u8> {
        let data = vec![0u8; ARP_LEN + ETH_LEN];

        let mut data_ptr_iter = UnsafeRefIter::new(&data);

        // let mut eth_header = unsafe{(data.as_ptr() as usize as *mut Eth).as_mut()}.unwrap();
        let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
        eth_header.rtype = EthRtype::ARP.into();
        eth_header.dhost = BROADCAST_MAC;
        eth_header.shost = self.sender_mac;

        // let mut arp_header = unsafe{((data.as_ptr() as usize + size_of::<Eth>()) as *mut Arp).as_mut()}.unwrap();
        let arp_header = unsafe { data_ptr_iter.next_mut::<Arp>() }.unwrap();
        arp_header.httype = ARP_HRD_ETHER.to_be();
        arp_header.pttype = EthRtype::IP.into();
        arp_header.hlen = ARP_ETHADDR_LEN as u8; // mac address len
        arp_header.plen = 4; // ipv4
        arp_header.op = self.rtype.to_u16().to_be();

        arp_header.sha = self.sender_mac;
        arp_header.spa = self.sender_ip;

        arp_header.tha = self.target_mac;
        arp_header.tpa = self.target_ip;
        data
    }

    pub fn reply_packet(&self, local_ip: Ipv4Addr, local_mac: MacAddress) -> Option<Self> {
        match self.rtype {
            ArpType::Request => {
                let reply_packet = ArpPacket::new(
                    local_ip,
                    local_mac,
                    self.sender_ip,
                    self.sender_mac,
                    ArpType::Reply,
                );

                Some(reply_packet)
            }
            _ => None,
        }
    }
}
