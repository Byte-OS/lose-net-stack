use core::fmt::Debug;

use crate::MacAddress;

pub trait NetInterface: Debug {
    fn send(data: &[u8]);
    fn local_mac_address() -> MacAddress;
}
