use core::{marker::PhantomData, net::SocketAddrV4};

use alloc::{collections::VecDeque, sync::Weak, vec::Vec};
use spin::Mutex;

use crate::{
    arp_table::get_mac_address,
    consts::{EthRtype, IpProtocal, BROADCAST_MAC, IP_HEADER_VHL},
    net::{Eth, Ip, ETH_LEN, IP_LEN, UDP, UDP_LEN},
    net_trait::NetInterface,
    utils::{check_sum, UnsafeRefIter},
    MacAddress,
};

use super::NetServer;

/// Udp server.
pub struct UdpServer<T: NetInterface> {
    pub source: SocketAddrV4,
    pub packets: Mutex<VecDeque<UdpConnPacket>>,
    pub server: Weak<NetServer<T>>,
    pub net: PhantomData<T>,
}

pub struct UdpConnPacket {
    pub addr: SocketAddrV4, // target address and socket.
    pub data: Vec<u8>,      // target data
}

impl<T: NetInterface> UdpServer<T> {
    pub fn receve_from(&self) -> Option<UdpConnPacket> {
        self.packets.lock().pop_front()
    }

    pub fn sendto(&self, addr: SocketAddrV4, buf: &[u8]) {
        log::debug!("send a udp message({} bytes) to {}", buf.len(), addr);

        if addr.ip().is_loopback() {
            let port = addr.port();
            if let Some(server) = self.server.upgrade() {
                server.get_udp(&port).map(|x| x.add_queue(self.source, buf));
            }
            return;
        }

        let data = vec![0u8; UDP_LEN + IP_LEN + ETH_LEN + buf.len()];

        // convert data ptr to the ref needed.
        let mut data_ptr_iter = UnsafeRefIter::new(&data);
        let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
        let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
        let udp_header = unsafe { data_ptr_iter.next_mut::<UDP>() }.unwrap();
        let udp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };

        eth_header.rtype = EthRtype::IP.into();
        // eth_header.shost = self.source_mac.to_bytes();
        // eth_header.dhost = self.dest_mac.to_bytes();
        eth_header.shost = MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        eth_header.dhost = BROADCAST_MAC;
        eth_header.shost = get_mac_address(self.source.ip()).unwrap_or(BROADCAST_MAC);
        eth_header.dhost = get_mac_address(addr.ip()).unwrap_or(BROADCAST_MAC);

        ip_header.pro = IpProtocal::UDP.into();
        ip_header.off = 0;
        // ip_header.src = self.source_ip.to_u32().to_be();
        // ip_header.dst = self.dest_ip.to_u32().to_be();
        ip_header.src = self.source.ip().clone();
        ip_header.dst = addr.ip().clone();
        ip_header.tos = 0; // type of service, use 0 as default
        ip_header.id = 0; // packet identified, use 0 as default
        ip_header.ttl = 100; // packet ttl, use 32 as default
        ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
        ip_header.len = ((buf.len() + UDP_LEN + IP_LEN) as u16).to_be(); // toal len
        ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum

        udp_header.sport = self.source.port().to_be();
        udp_header.dport = addr.port().to_be();
        udp_header.sum = 0; // udp checksum   zero means no checksum is provided.
        udp_header.ulen = ((buf.len() + UDP_LEN) as u16).to_be();

        udp_data.copy_from_slice(&buf);

        T::send(&data);
    }

    pub fn add_queue(&self, addr: SocketAddrV4, data: &[u8]) {
        self.packets.lock().push_back(UdpConnPacket {
            addr,
            data: data.to_vec(),
        })
    }
}
