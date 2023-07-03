use core::{net::{SocketAddr, SocketAddrV4, Ipv4Addr}, marker::PhantomData};

use alloc::collections::BTreeMap;

use crate::{MacAddress, net::{Eth, TCP_LEN, IP_LEN, TCP, Ip, UDP_LEN, UDP, Arp}, utils::UnsafeRefIter, results::Packet, packets::{arp::{ArpType, ArpPacket}, self}, IPv4, consts::{IP_HEADER_VHL, ETH_RTYPE_IP, ETH_RTYPE_ARP, IP_PROTOCAL_UDP, IP_PROTOCAL_TCP, IP_PROTOCAL_ICMP}, net_trait::NetInterface};

use self::udp::UdpServer;

pub mod tcp;
pub mod udp;

pub struct NetServer<T: NetInterface> {
    local_mac: MacAddress,
    local_ip: Ipv4Addr,
    tcp_map: BTreeMap<usize, SocketAddr>,
    udp_map: BTreeMap<usize, UdpServer>,
    net: PhantomData<T>
}

impl<T: NetInterface> NetServer<T> {
    pub fn new(local_mac: MacAddress, local_ip: Ipv4Addr) -> Self {
        Self {
            local_mac,
            local_ip,
            tcp_map: BTreeMap::new(),
            udp_map: BTreeMap::new(),
            net: PhantomData
        }
    }
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
    pub fn get_local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }
    /// analysis net code.
    pub fn analysis_net_data(&self, data: &[u8]) {
        debug!("analusis net data");
        let mut data_ptr_iter = UnsafeRefIter::new(data);
        let eth_header = unsafe { data_ptr_iter.next::<Eth>() }.unwrap();
        debug!("eth header: {:?}  type: {:#x}", eth_header, eth_header.rtype.to_be());
        match eth_header.rtype.to_be() {
            ETH_RTYPE_IP => self.analysis_ip(data_ptr_iter, eth_header),
            ETH_RTYPE_ARP => self.analysis_arp(data_ptr_iter),
            _ => {}, // Unsupported type. Do nothing.
        };
    }
}

impl<T: NetInterface> NetServer<T> {
    fn analysis_udp(
        &self,
        mut data_ptr_iter: UnsafeRefIter,
        ip_header: &Ip,
        eth_header: &Eth,
    ) -> Packet {
        let udp_header = unsafe { data_ptr_iter.next::<UDP>() }.unwrap();
        let data = unsafe { data_ptr_iter.get_curr_arr() };
        let data_len = ip_header.len.to_be() as usize - UDP_LEN - IP_LEN;

        debug!("receive a udp packet: {:?}", data);

        Packet::UDP(packets::udp::UDPPacket {
            source_ip: IPv4::from_u32(ip_header.src.to_be()),
            source_mac: MacAddress::new(eth_header.shost),
            source_port: udp_header.sport.to_be(),
            dest_ip: IPv4::from_u32(ip_header.dst.to_be()),
            dest_mac: MacAddress::new(eth_header.dhost),
            dest_port: udp_header.dport.to_be(),
            data_len,
            data: &data[..data_len],
        })
    }

    fn analysis_tcp(
        &self,
        mut data_ptr_iter: UnsafeRefIter,
        ip_header: &Ip,
        eth_header: &Eth,
    ) -> Packet {
        let tcp_header = unsafe { data_ptr_iter.next::<TCP>() }.unwrap();
        let offset = ((tcp_header.offset >> 4 & 0xf) as usize - 5) * 4;
        let data = &unsafe { data_ptr_iter.get_curr_arr() }[offset..];
        let data_len = ip_header.len.to_be() as usize - TCP_LEN - IP_LEN - offset;

        Packet::TCP(packets::tcp::TCPPacket {
            source_ip: IPv4::from_u32(ip_header.src.to_be()),
            source_mac: MacAddress::new(eth_header.shost),
            source_port: tcp_header.sport.to_be(),
            dest_ip: IPv4::from_u32(ip_header.dst.to_be()),
            dest_mac: MacAddress::new(eth_header.dhost),
            dest_port: tcp_header.dport.to_be(),
            data_len,
            seq: tcp_header.seq.to_be(),
            ack: tcp_header.ack.to_be(),
            flags: tcp_header.flags,
            win: tcp_header.win.to_be(),
            urg: tcp_header.urg.to_be(),
            data,
        })
    }

    fn analysis_icmp(
        &self,
        data_ptr_iter: UnsafeRefIter,
        _ip_header: &Ip,
        _eth_header: &Eth,
    ) -> Packet {
        let _data = unsafe { data_ptr_iter.get_curr_arr() };

        Packet::ICMP()
    }

    fn analysis_ip(&self, mut data_ptr_iter: UnsafeRefIter, eth_header: &Eth) {
        let ip_header = unsafe { data_ptr_iter.next::<Ip>() }.unwrap();

        if ip_header.vhl != IP_HEADER_VHL {
            // return Packet::None;
            return;
        }

        // judge whether the ip header is self
        // if ip_header.dst.to_be() != self.local_ip.ip() {
        //     return Packet::None;
        // }

        let send_packet = match ip_header.pro {
            IP_PROTOCAL_UDP => self.analysis_udp(data_ptr_iter, ip_header, eth_header),
            IP_PROTOCAL_TCP => self.analysis_tcp(data_ptr_iter, ip_header, eth_header),
            IP_PROTOCAL_ICMP => self.analysis_icmp(data_ptr_iter, ip_header, eth_header),
            _ => Packet::None,
        };
    }

    fn analysis_arp(&self, mut data_ptr_iter: UnsafeRefIter) {
        let arp_header = unsafe { data_ptr_iter.next::<Arp>() }.unwrap();
        if arp_header.hlen != 6 || arp_header.plen != 4 {
            // Unsupported now
            log::warn!("can't support the case that not ipv4")
        } else {
            let rtype = ArpType::form_u16(arp_header.op.to_be());
            let arp = ArpPacket::new(
                IPv4::from_u32(arp_header.spa.to_be()),
                MacAddress::new(arp_header.sha),
                IPv4::from_u32(arp_header.tpa.to_be()),
                MacAddress::new(arp_header.tha),
                rtype,
            );
            let ipv4 = self.local_ip.octets();
            let send_data = arp.reply_packet(IPv4::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3]), self.local_mac).expect("can't build reply").build_data();
            // TODO: Send arp packet data.
            T::send(&send_data);
        }
    }
}