use crate::packets::{udp::UDPPacket, arp::ArpPacket, tcp::TCPPacket};

#[derive(Debug)]
pub enum Packet {
    ARP(ArpPacket),
    UDP(UDPPacket<'static>),
    TCP(TCPPacket<'static>),
    ICMP(),
    IGMP(),
    Todo(&'static str),
    None
}

#[derive(Debug)]
pub enum NetStackErrors {
    NotRequiredReplyArp,
}