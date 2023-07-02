use core::net::SocketAddr;

use alloc::collections::BTreeMap;

use crate::MacAddress;

pub mod tcp;
pub mod udp;

pub struct NetServer {
    local_mac: MacAddress,
    local_ip: SocketAddr,
    tcp_map: BTreeMap<usize, SocketAddr>,
    udp_map: BTreeMap<usize, SocketAddr>,
}

impl NetServer {
    /// return whether the tcp port has been used.
    pub fn tcp_is_used(&self, port: usize) -> bool {
        self.tcp_map.get(&port).is_some()
    }
    /// return whether the udp port has been used.
    pub fn udp_is_used(&self, port: usize) -> bool {
        self.udp_map.get(&port).is_some()
    }
    /// return the local mac address.
    pub fn get_local_mac(&self) -> MacAddress {
        self.local_mac
    }
    /// return the local ip address.
    pub fn get_local_ip(&self) -> SocketAddr {
        self.local_ip
    }
}
