use core::marker::PhantomData;
use core::net::{Ipv4Addr, SocketAddrV4};

use alloc::vec::Vec;
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use spin::Mutex;

use crate::arp_table::cache_arp_entry;
use crate::consts::{
    IP_HEADER_VHL, IpProtocal,
};
use crate::net::{Arp, Eth, Ip, IP_LEN, TCP, TCP_LEN, UDP};
use crate::net_trait::NetInterface;
use crate::packets::{
    arp::{ArpPacket, ArpType},
};
use crate::results::{NetServerError};
use crate::utils::UnsafeRefIter;
use crate::{MacAddress, TcpFlags};

use self::tcp::TcpServer;
use self::udp::UdpServer;

pub mod tcp;
pub mod udp;

pub struct NetServer<T: NetInterface> {
    local_mac: MacAddress,
    local_ip: Ipv4Addr,
    tcp_map: Mutex<BTreeMap<u16, Arc<TcpServer<T>>>>,
    udp_map: Mutex<BTreeMap<u16, Arc<UdpServer<T>>>>,
    net: PhantomData<T>,
}

impl<T: NetInterface> NetServer<T> {
    pub const fn new(local_mac: MacAddress, local_ip: Ipv4Addr) -> Self {
        Self {
            local_mac,
            local_ip,
            tcp_map: Mutex::new(BTreeMap::new()),
            udp_map: Mutex::new(BTreeMap::new()),
            net: PhantomData,
        }
    }
    /// return whether the tcp port has been used.
    pub fn tcp_is_used(&self, port: u16) -> bool {
        self.tcp_map.lock().get(&port).is_some()
    }
    /// return whether the udp port has been used.
    pub fn udp_is_used(&self, port: u16) -> bool {
        self.udp_map.lock().get(&port).is_some()
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
        debug!(
            "eth header: {:?}  type: {:?}",
            eth_header,
            eth_header.rtype
        );
        match eth_header.rtype {
            crate::consts::EthRtype::IP => self.analysis_ip(data_ptr_iter, eth_header),
            crate::consts::EthRtype::ARP => self.analysis_arp(data_ptr_iter),
            crate::consts::EthRtype::Unknown => {},
        }
        // match eth_header.rtype.to_be() {
        //     ETH_RTYPE_IP => self.analysis_ip(data_ptr_iter, eth_header),
        //     ETH_RTYPE_ARP => self.analysis_arp(data_ptr_iter),
        //     _ => {} // Unsupported type. Do nothing.
        // };

    }
    /// listen on a tcp port
    pub fn listen_udp(self: &Arc<Self>, port: u16) -> Result<Arc<UdpServer<T>>, NetServerError> {
        let udp_server = Arc::new(UdpServer::<T> {
            source: SocketAddrV4::new(self.local_ip, port),
            packets: Mutex::new(VecDeque::new()),
            server: Arc::downgrade(&self),
            net: PhantomData,
        });
        self.udp_map.lock().insert(port, udp_server.clone());
        Ok(udp_server)
    }
    /// get udp server
    pub fn get_udp(&self, port: &u16) -> Option<Arc<UdpServer<T>>> {
        self.udp_map.lock().get(port).cloned()
    }

    /// listen on a tcp port
    pub fn listen_tcp(self: &Arc<Self>, port: u16) -> Result<Arc<TcpServer<T>>, NetServerError> {
        let tcp_server = Arc::new(TcpServer::<T> {
            source: SocketAddrV4::new(self.local_ip, port),
            clients: Mutex::new(Vec::new()),
            wait_queue: Mutex::new(VecDeque::new()),
        });
        self.tcp_map.lock().insert(port, tcp_server.clone());
        Ok(tcp_server)
    }
    /// get tcp server
    pub fn get_tcp(&self, port: &u16) -> Option<Arc<TcpServer<T>>> {
        self.tcp_map.lock().get(port).cloned()
    }
}

impl<T: NetInterface> NetServer<T> {
    fn analysis_udp(&self, mut data_ptr_iter: UnsafeRefIter, ip_header: &Ip) {
        let udp_header = unsafe { data_ptr_iter.next::<UDP>() }.unwrap();
        let data = unsafe { data_ptr_iter.get_curr_arr() };

        debug!(
            "receive a udp packet: {:?} from {:?}:{}",
            data,
            ip_header.src,
            udp_header.sport.to_be()
        );

        let local_port = udp_header.dport.to_be();
        let remote_ip = ip_header.src;
        let remote_port = udp_header.sport.to_be();
        if let Some(udp_conn) = self.udp_map.lock().get(&local_port) {
            udp_conn.add_queue(SocketAddrV4::new(remote_ip, remote_port), data)
        }
    }

    fn analysis_tcp(&self, mut data_ptr_iter: UnsafeRefIter, ip_header: &Ip) {
        let tcp_header = unsafe { data_ptr_iter.next::<TCP>() }.unwrap();
        let offset = ((tcp_header.offset >> 4 & 0xf) as usize - 5) * 4;
        let data = &unsafe { data_ptr_iter.get_curr_arr() }[offset..];
        let data_len = ip_header.len.to_be() as usize - TCP_LEN - IP_LEN - offset;

        debug!("receive a {} bytes data packet from {}, flags: {:?}", data_len, ip_header.src, tcp_header.flags);
        
        let connection = self.get_tcp(&tcp_header.dport.to_be());
        if connection.is_none() {
            return;
        }
        let connection = connection.unwrap();

        if tcp_header.flags.contains(TcpFlags::S) {
            debug!("receive a tcp connection from {}, tcp_header: {:#x?}", ip_header.src, tcp_header);
            connection.add_queue(SocketAddrV4::new(ip_header.src, tcp_header.sport.to_be()), tcp_header.seq.to_be(), tcp_header.ack.to_be())
        }
        // Packet::TCP(packets::tcp::TCPPacket {
        //     source_ip: IPv4::from_u32(ip_header.src.to_be()),
        //     source_mac: MacAddress::new(eth_header.shost),
        //     source_port: tcp_header.sport.to_be(),
        //     dest_ip: IPv4::from_u32(ip_header.dst.to_be()),
        //     dest_mac: MacAddress::new(eth_header.dhost),
        //     dest_port: tcp_header.dport.to_be(),
        //     data_len,
        //     seq: tcp_header.seq.to_be(),
        //     ack: tcp_header.ack.to_be(),
        //     flags: tcp_header.flags,
        //     win: tcp_header.win.to_be(),
        //     urg: tcp_header.urg.to_be(),
        //     data,
        // });
    }

    fn analysis_icmp(&self, data_ptr_iter: UnsafeRefIter, _ip_header: &Ip, _eth_header: &Eth) {
        let _data = unsafe { data_ptr_iter.get_curr_arr() };

        // Packet::ICMP();
    }

    fn analysis_ip(&self, mut data_ptr_iter: UnsafeRefIter, eth_header: &Eth) {
        let ip_header = unsafe { data_ptr_iter.next::<Ip>() }.unwrap();

        // judge whether the ip header is self
        if ip_header.vhl != IP_HEADER_VHL || ip_header.dst != self.local_ip {
            // return Packet::None;
            return;
        }

        let remote_ip = ip_header.src;
        let remote_mac = eth_header.shost;
        cache_arp_entry(remote_ip, remote_mac);

        // match ip_header.pro {
        //     IP_PROTOCAL_UDP => self.analysis_udp(data_ptr_iter, ip_header),
        //     IP_PROTOCAL_TCP => self.analysis_tcp(data_ptr_iter, ip_header, eth_header),
        //     IP_PROTOCAL_ICMP => self.analysis_icmp(data_ptr_iter, ip_header, eth_header),
        //     _ => {}
        // };
        match ip_header.pro {
            IpProtocal::IGMP => {},
            IpProtocal::ICMP => self.analysis_icmp(data_ptr_iter, ip_header, eth_header),
            IpProtocal::TCP => self.analysis_tcp(data_ptr_iter, ip_header),
            IpProtocal::UDP => self.analysis_udp(data_ptr_iter, ip_header),
            IpProtocal::Unknown => {},
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
                arp_header.spa,
                arp_header.sha,
                arp_header.tpa,
                arp_header.tha,
                rtype,
            );
            let send_data = arp
                .reply_packet(
                    self.local_ip,
                    self.local_mac,
                )
                .expect("can't build reply")
                .build_data();
            // TODO: Send arp packet data.
            T::send(&send_data);
        }
    }
}
