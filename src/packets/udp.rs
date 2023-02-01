use alloc::boxed::Box;

use crate::{MacAddress, IPv4};

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
}