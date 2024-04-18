use core::{mem::size_of, net::Ipv4Addr};

use crate::{
    consts::{EthRtype, IpProtocal},
    MacAddress,
};

#[derive(Debug)]
#[repr(C)]
pub struct Eth {
    pub(crate) dhost: MacAddress, // destination host
    pub(crate) shost: MacAddress, // source host
    pub(crate) rtype: EthRtype,   // packet type, arp or ip
}

#[repr(packed)]
#[derive(Debug, Clone)]
pub struct Arp {
    pub(crate) httype: u16,      // Hardware type
    pub(crate) pttype: EthRtype, // Protocol type, For IPv4, this has the value 0x0800.
    pub(crate) hlen: u8,         // Hardware length: Ethernet address length is 6.
    pub(crate) plen: u8,         // Protocol length: IPv4 address length is 4.
    pub(crate) op: u16,          // Operation: 1 for request, 2 for reply.
    pub(crate) sha: MacAddress,  // Sender hardware address
    pub(crate) spa: Ipv4Addr,    // Sender protocol address
    pub(crate) tha: MacAddress,  // Target hardware address
    pub(crate) tpa: Ipv4Addr,    // Target protocol address
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Debug, Clone)]
pub struct Ip {
    pub(crate) vhl: u8,         // version << 4 | header length >> 2
    pub(crate) tos: u8,         // type of service
    pub(crate) len: u16,        // total length, packet length
    pub(crate) id: u16,         // identification, can combine all packets
    pub(crate) off: u16,        // fragment offset field, packet from
    pub(crate) ttl: u8,         // time to live
    pub(crate) pro: IpProtocal, // protocol， ICMP(1)、IGMP(2)、TCP(6)、UDP(17)
    pub(crate) sum: u16,        // checksum,
    pub(crate) src: Ipv4Addr,   // souce ip
    pub(crate) dst: Ipv4Addr,   // destination ip
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct UDP {
    pub(crate) sport: u16, // souce port
    pub(crate) dport: u16, // destination port
    pub(crate) ulen: u16,  // length, including udp header, not including IP header
    pub(crate) sum: u16,   // checksum
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TcpFlags: u8 {
        const NONE = 0;
        const F = 0b00000001;
        const S = 0b00000010;
        const R = 0b00000100;
        const P = 0b00001000;
        const A = 0b00010000;
        const U = 0b00100000;
    }
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct TCP {
    pub(crate) sport: u16,      // souce port
    pub(crate) dport: u16,      // destination port
    pub(crate) seq: u32,        // sequence number
    pub(crate) ack: u32,        // acknowledgement number
    pub(crate) offset: u8,      // offset, first 4 bytes are tcp header length
    pub(crate) flags: TcpFlags, // flags, last 6 are flags(U, A, P, R, S, F)
    pub(crate) win: u16,        // window size
    pub(crate) sum: u16,        // checksum
    pub(crate) urg: u16,        // urgent pointer
}

#[allow(dead_code)]
#[repr(packed)]
#[derive(Debug, Clone, Copy)]
pub struct ICMP {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) checksum: u16,
    pub(crate) id: u16,
    pub(crate) seq: u16,
}

pub(crate) const ETH_LEN: usize = size_of::<Eth>();
pub(crate) const ARP_LEN: usize = size_of::<Arp>();
pub(crate) const IP_LEN: usize = size_of::<Ip>();
pub(crate) const UDP_LEN: usize = size_of::<UDP>();
pub(crate) const TCP_LEN: usize = size_of::<TCP>();
