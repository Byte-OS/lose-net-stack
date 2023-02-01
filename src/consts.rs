// mac address
pub(crate) const BROADCAST_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

// eth
pub(crate) const ETH_RTYPE_IP: u16 =  0x0800; // Internet protocol
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