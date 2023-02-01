use crate::packets::{udp::UDPPacket, arp::ArpPacket};

#[derive(Debug)]
pub enum Packet {
    ARP(ArpPacket),
    UDP(UDPPacket),
    TCP(),
    ICMP(),
    IGMP(),
    Todo(&'static str),
    None
}

#[derive(Debug)]
pub enum NetStackErrors {
    NotRequiredReplyArp,
}