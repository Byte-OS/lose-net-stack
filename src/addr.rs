use core::fmt::{Display, Debug, Pointer};

use alloc::{string::String, format, fmt::format};

#[derive(Clone, Copy)]
pub struct IPv4(u32);

impl IPv4 {
    pub fn new(a1: u8, a2: u8, a3: u8, a4: u8) -> Self {
        IPv4((a1 as u32) << 24 | (a2 as u32) << 16 | (a3 as u32) << 8 | (a4 as u32))
    }

    pub fn from_u32(ip: u32) -> Self {
        IPv4(ip)
    }

    pub fn to_string(&self) -> String {
        format!("{}.{}.{}.{}", (self.0 >> 24) & 0xff, (self.0 >> 16) & 0xff, (self.0 >> 8) & 0xff, self.0 & 0xff)
    }

    pub fn to_u32(&self) -> u32 {
        self.0
    }
}
impl Display for IPv4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Debug for IPv4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("IPv4").field(&self.to_string()).finish()
    }
}

#[derive(Clone, Copy)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    pub fn new(addr: [u8; 6]) -> Self {
        MacAddress(addr)
    }

    pub fn to_bytes(&self) -> [u8; 6] {
        self.0
    }

    pub fn to_string(&self) -> String {
        format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

impl Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Debug for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MacAddress").field(&self.to_string()).finish()
    }
}