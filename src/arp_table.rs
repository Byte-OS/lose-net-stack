use core::net::Ipv4Addr;

use alloc::collections::BTreeMap;
use spin::Mutex;

use crate::MacAddress;

pub static ARP_TABLE: Mutex<BTreeMap<Ipv4Addr, MacAddress>> = Mutex::new(BTreeMap::new());

/// get the mac address for the given ip address
pub fn get_mac_address(ipv4: &Ipv4Addr) -> Option<MacAddress> {
    ARP_TABLE.lock().get(ipv4).cloned()
}

/// cache the mac address for the given ip address
pub fn cache_arp_entry(ipv4: Ipv4Addr, mac: MacAddress) {
    ARP_TABLE.lock().insert(ipv4, mac);
}
