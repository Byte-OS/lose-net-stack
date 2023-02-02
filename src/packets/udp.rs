use alloc::{boxed::Box, vec::Vec};

use crate::consts::{ETH_RTYPE_IP, IP_PROTOCAL_UDP};
use crate::net::{UDP, Eth, Ip, UDP_LEN, IP_LEN, ETH_LEN};
use crate::IPv4;
use crate::MacAddress;
use crate::utils::UnsafeRefIter;

#[derive(Debug, Clone)]
pub struct UDPPacket {
    pub source_ip: IPv4,
    pub source_mac: MacAddress,
    pub source_port: u16,
    pub dest_ip: IPv4,
    pub dest_mac: MacAddress,
    pub dest_port: u16,
    pub data_len: usize,
    pub data: Box<&'static [u8]>
}

impl UDPPacket {
    pub fn new(source_ip: IPv4, source_mac: MacAddress, source_port: u16, 
        dest_ip: IPv4, dest_mac: MacAddress, dest_port: u16, 
        data_len: usize, data: Box<&'static [u8]>) -> Self {
        Self {
            source_ip,
            source_mac,
            source_port,
            dest_ip,
            dest_mac,
            dest_port,
            data_len,
            data
        }
    }

    pub fn build_data(&self) -> Vec<u8> {
        let mut data = vec![0u8; UDP_LEN + IP_LEN + ETH_LEN + self.data_len];

        let mut data_ptr_iter = UnsafeRefIter::new(&data);
        let eth_header = unsafe{data_ptr_iter.next::<Eth>()}.unwrap();
        let ip_header = unsafe{data_ptr_iter.next::<Ip>()}.unwrap();
        let udp_header = unsafe{data_ptr_iter.next::<UDP>()};
        let mut udp_data = unsafe {data_ptr_iter.get_curr_arr_mut()};
        // let eth_header = unsafe {data.as_mut_ptr().cast::<Eth>().as_mut()}.unwrap();
        // let ip_header = unsafe { data.as_mut_ptr().add(ETH_LEN).cast::<Ip>().as_mut() }.unwrap();
        // let udp_header = unsafe { data.as_mut_ptr().add(ETH_LEN + IP_LEN).cast::<UDP>().as_mut() }.unwrap();

        eth_header.rtype = ETH_RTYPE_IP.to_be();
        eth_header.shost = self.source_mac.to_bytes();
        eth_header.dhost = self.dest_mac.to_bytes();
        
        ip_header.pro = IP_PROTOCAL_UDP.to_be();
        ip_header.off = 0;
        ip_header.src = self.source_ip.to_u32().to_be();
        ip_header.dst = self.dest_ip.to_u32().to_be();
        ip_header.tos = todo!(); // type of service
        ip_header.id  = todo!(); // packet identified
        ip_header.sum = todo!(); // checksum
        ip_header.ttl = todo!(); // packet ttl
        ip_header.vhl = todo!(); // version << 4 | header length >> 2
        ip_header.len = todo!(); // toal len

        udp_header.sport = self.source_port;
        udp_header.dport = self.dest_port;
        udp_header.sum   = todo!(); // udp checksum
        udp_header.ulen  = (self.data_len + UDP_LEN) as _;

        udp_data.copy_from_slice(&self.data);

        data
    }
}