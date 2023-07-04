use core::default;

use num_enum::FromPrimitive;

use crate::MacAddress;

// mac address
pub(crate) const BROADCAST_MAC: MacAddress = MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

// eth
pub(crate) const ETH_RTYPE_IP: u16 = 0x0800; // Internet protocol
pub(crate) const ETH_RTYPE_ARP: u16 = 0x0806; // Address resolution protocol

// arp
pub(crate) const ARP_HRD_ETHER: u16 = 1;
pub(crate) const ARP_PTYPE_ETHTYPE_IP: u16 = 0x0800;
pub(crate) const ARP_ETHADDR_LEN: usize = 6;
pub(crate) const ARP_OP_REQUEST: u16 = 1;
pub(crate) const ARP_OP_REPLY: u16 = 2;

// ip packet
pub(crate) const IP_PROTOCAL_ICMP: u8 = 1;
pub(crate) const IP_PROTOCAL_IGMP: u8 = 2;
pub(crate) const IP_PROTOCAL_TCP: u8 = 6;
pub(crate) const IP_PROTOCAL_UDP: u8 = 17;

pub(crate) const IP_HEADER_VHL: u8 = 4 << 4 | 20 >> 2;

pub(crate) const TCP_EMPTY_DATA: &[u8] = &[];

#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u16)]
pub enum EthRtype {
    IP = 0x0008,
    ARP = 0x0608,
    #[num_enum(default)]
    Unknown
}

#[derive(Debug, Eq, PartialEq, FromPrimitive)]
#[repr(u8)]
pub enum IpProtocal {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    #[num_enum(default)]
    Unknown
}