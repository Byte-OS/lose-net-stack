use core::net::SocketAddrV4;

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use spin::Mutex;

use crate::{
    arp_table::get_mac_address,
    consts::{BROADCAST_MAC, ETH_RTYPE_IP, IP_HEADER_VHL, IP_PROTOCAL_UDP},
    net::{Eth, Ip, ETH_LEN, IP_LEN, UDP, UDP_LEN},
    utils::{check_sum, UnsafeRefIter},
};

/// Udp server.
pub struct UdpServer {
    pub source: SocketAddrV4,
    pub clients: Mutex<Vec<Arc<UdpConnection>>>,
    pub wait_queue: Mutex<VecDeque<Arc<UdpConnection>>>,
}

impl UdpServer {
    /// this function will create a new udp connection.
    pub fn accept(&self) -> Option<Arc<UdpConnection>> {
        if let Some(client) = self.wait_queue.lock().pop_front() {
            self.clients.lock().push(client.clone());
            Some(client)
        } else {
            None
        }
    }
    /// add a wait client queue to server.
    pub fn add_queue(self: Arc<Self>, remote: SocketAddrV4) {
        self.wait_queue.lock().push_back(Arc::new(UdpConnection {
            source: self.source,
            remote,
            datas: Mutex::new(vec![]),
            server: Arc::downgrade(&self),
        }))
    }
}

/// Udp connection.
pub struct UdpConnection {
    pub source: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub datas: Mutex<Vec<Vec<u8>>>,
    pub server: Weak<UdpServer>,
}

impl UdpConnection {
    /// send a message to the target.
    pub fn send(&self, data: &[u8]) {
        log::debug!("send a udp message to {}", self.remote);

        let data = vec![0u8; UDP_LEN + IP_LEN + ETH_LEN + data.len()];

        // convert data ptr to the ref needed.
        let mut data_ptr_iter = UnsafeRefIter::new(&data);
        let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
        let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
        let udp_header = unsafe { data_ptr_iter.next_mut::<UDP>() }.unwrap();
        let udp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };

        eth_header.rtype = ETH_RTYPE_IP.to_be();
        // eth_header.shost = self.source_mac.to_bytes();
        // eth_header.dhost = self.dest_mac.to_bytes();
        eth_header.shost = get_mac_address(self.source.ip())
            .map(|x| x.to_bytes())
            .unwrap_or(BROADCAST_MAC);
        eth_header.dhost = get_mac_address(self.remote.ip())
            .map(|x| x.to_bytes())
            .unwrap_or(BROADCAST_MAC);

        ip_header.pro = IP_PROTOCAL_UDP.to_be();
        ip_header.off = 0;
        // ip_header.src = self.source_ip.to_u32().to_be();
        // ip_header.dst = self.dest_ip.to_u32().to_be();
        // ip_header.src = self.source_ip.to_u32().to_be();
        // ip_header.dst = self.dest_ip.to_u32().to_be();
        ip_header.tos = 0; // type of service, use 0 as default
        ip_header.id = 0; // packet identified, use 0 as default
        ip_header.ttl = 100; // packet ttl, use 32 as default
        ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
        ip_header.len = ((data.len() + UDP_LEN + IP_LEN) as u16).to_be(); // toal len
        ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum

        udp_header.sport = self.source.port().to_be();
        udp_header.dport = self.remote.port().to_be();
        udp_header.sum = 0; // udp checksum   zero means no checksum is provided.
        udp_header.ulen = ((data.len() + UDP_LEN) as u16).to_be();

        udp_data.copy_from_slice(&data);

        // try to send the Message.
        // data
    }
    /// receive a message from the source.
    pub fn receive(&self) -> Option<Vec<u8>> {
        todo!()
    }
    /// this function is called when the interrupt occurs.
    pub fn interrupt(&self, data: &[u8]) {
        self.datas.lock().push(data.to_vec())
    }
}

impl Drop for UdpConnection {
    fn drop(&mut self) {
        if let Some(server) = self.server.upgrade() {
            server.clients.lock().retain(|c| c.source != self.source);
        }
    }
}
