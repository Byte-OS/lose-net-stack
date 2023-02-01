#[derive(Debug)]
#[repr(C)]
pub struct Eth {
    pub(crate) dhost: [u8; 6], // destination host
    pub(crate) shost: [u8; 6], // source host
    pub(crate) rtype: u16      // packet type, arp or ip
}