use core::marker::PhantomData;
use core::net::{SocketAddr, SocketAddrV4};

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{RwLock, Mutex};

use crate::TcpFlags;
use crate::arp_table::get_mac_address;
use crate::consts::{EthRtype, IpProtocal, IP_HEADER_VHL, BROADCAST_MAC};
use crate::net::{TCP_LEN, IP_LEN, ETH_LEN, Eth, Ip, TCP};
use crate::net_trait::NetInterface;
use crate::utils::{UnsafeRefIter, check_sum};

pub struct TcpServer<T: NetInterface> {
    pub source: SocketAddrV4,
    pub clients: Mutex<Vec<Arc<TcpConnection<T>>>>,
    pub wait_queue: Mutex<VecDeque<Arc<TcpConnection<T>>>>,
}

impl<T: NetInterface> TcpServer<T> {
    pub fn accept(&self) -> Option<Arc<TcpConnection<T>>> {
        if let Some(conn) = self.wait_queue.lock().pop_front() {
            self.clients.lock().push(conn.clone());
            conn.syn_ack();
            debug!("conn: {:?}", conn);
            Some(conn)
        } else {
            None
        }
    }

    pub fn add_queue(&self, remote: SocketAddrV4, seq: u32, ack: u32) {
        debug!("seq: {:?}", seq);
        let conn = Arc::new(TcpConnection { 
            local: self.source.clone(), 
            remote: RwLock::new(remote), 
            net: PhantomData, 
            options: Mutex::new(TcpSeq { 
                seq: 0,
                ack: seq + 1,
                window: 65535, 
                urg: 0
            }), 
            status: RwLock::new(TcpStatus::WaitingForConnect), 
            datas: Mutex::new(VecDeque::new())
        });
        self.wait_queue.lock().push_back(conn);
    }
}

#[derive(Debug)]
pub struct TcpSeq {
    seq: u32,
    ack: u32,
    window: u16,
    urg: u16,   // default value is 0
}

#[derive(Debug, Clone, Copy)]
pub enum TcpStatus {
    WaitingForConnect,
    WaitingForAck,
    WaitingForData,
    WaitingForFin,
}

#[derive(Debug)]
pub struct TcpConnection<T: NetInterface> {
    pub local: SocketAddrV4,
    pub remote: RwLock<SocketAddrV4>,
    pub net: PhantomData<T>,
    pub options: Mutex<TcpSeq>,
    pub status: RwLock<TcpStatus>,
    pub datas: Mutex<VecDeque<Vec<u8>>>
}

impl<T: NetInterface> TcpConnection<T> {
    pub fn connect(&self, remote: SocketAddrV4) {
        *self.remote.write() = remote;
    }

    pub fn send(&self, buf:&[u8]) -> usize {
        self.send_data(buf, TcpFlags::NONE);
        buf.len()
    }

    pub fn send_data(&self, buf: &[u8], flags: TcpFlags) {
        let remote = self.remote.read();
        let options = self.options.lock();
        debug!("options: {:?}", options);

        let data = vec![0u8; TCP_LEN + IP_LEN + ETH_LEN + buf.len()];
        // convert data ptr to the ref needed.
        let mut data_ptr_iter = UnsafeRefIter::new(&data);
        let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
        let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
        let tcp_header = unsafe { data_ptr_iter.next_mut::<TCP>() }.unwrap();
        let tcp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };
        eth_header.rtype = EthRtype::IP;
        eth_header.shost = T::local_mac_address();
        // eth_header.dhost = BROADCAST_MAC;
        eth_header.dhost = get_mac_address(&remote.ip()).unwrap_or(BROADCAST_MAC);
        // eth_header.shost = self.source_mac.to_bytes();
        // eth_header.dhost = self.dest_mac.to_bytes();
        ip_header.pro =IpProtocal::TCP;
        ip_header.off = 0;
        ip_header.src = self.local.ip().clone();
        ip_header.dst = *remote.ip();
        ip_header.tos = 0; // type of service, use 0 as default
        ip_header.id = 0; // packet identified, use 0 as default
        ip_header.ttl = 100; // packet ttl, use 32 as default
        ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
        ip_header.len = ((buf.len() + TCP_LEN + IP_LEN) as u16).to_be(); // toal len
        ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum
        tcp_header.sport = self.local.port().to_be();
        tcp_header.dport = remote.port().to_be();
        tcp_header.offset = 5 << 4;
        tcp_header.seq = options.seq.to_be();
        tcp_header.ack = options.ack.to_be();
        // tcp_header.flags = self.flags;
        tcp_header.flags = flags;
        tcp_header.win = options.window.to_be();
        tcp_header.urg = options.urg;
        tcp_header.sum = 0;
        tcp_data.copy_from_slice(buf);
        debug!("ip: {:?}", self.local.ip().octets());
        let mut sum = self.local.ip().octets().iter().rev().fold(0, |acc, x| acc << 8 | *x as u32);
        debug!("sum: {:#x}", sum);
        sum += remote.ip().octets().iter().rev().fold(0, |acc, x| acc << 8 | *x as u32);
        sum += (IpProtocal::TCP as u16).to_be() as u32;
        sum += ((buf.len() + TCP_LEN) as u16).to_be() as u32;
        tcp_header.sum = check_sum(
            tcp_header as *mut _ as *mut u8,
            (TCP_LEN + buf.len()) as _,
            sum,
        ); // tcp checksum. zero means no checksum is provided.
        T::send(&data);
    }

    pub fn syn_ack(&self) {
        self.send_data(&[], TcpFlags::S | TcpFlags::A);
    }

    pub fn interrupt(&self, data: &[u8], seq: u32, ack: u32, flags: TcpFlags) {
        let status = self.status.read().clone();

        match status {
            TcpStatus::WaitingForData => {
                self.datas.lock().push_back(data.to_vec());
                let mut seq = seq + data.len() as u32;
                // according to rfc793, the SYN consume one byte in the stream.
                if flags.contains(TcpFlags::S) || flags.contains(TcpFlags::F) {
                    seq += 1;
                }
                let mut options = self.options.lock();
                options.seq = ack;
                options.ack = seq;
            },
            _ => {
                warn!("can't receive data from the interrupt stream.")
            }
        }
    }
}

// impl TcpServer {
//     /// this function will create a new udp connection.
//     pub fn accept(&self) -> Option<Arc<UdpConnection>> {
//         if let Some(client) = self.wait_queue.lock().pop_front() {
//             self.clients.lock().push(client.clone());
//             Some(client)
//         } else {
//             None
//         }
//     }
//     /// add a wait client queue to server.
//     pub fn add_queue(self: Arc<Self>, remote: SocketAddrV4) {
//         self.wait_queue.lock().push_back(Arc::new(UdpConnection {
//             source: self.source,
//             remote,
//             datas: Mutex::new(vec![]),
//             server: Arc::downgrade(&self),
//         }))
//     }
// }

// /// Udp connection.
// pub struct UdpConnection {
//     pub source: SocketAddrV4,
//     pub remote: SocketAddrV4,
//     pub datas: Mutex<Vec<Vec<u8>>>,
//     pub server: Weak<UdpServer>,
// }

// impl UdpConnection {
//     /// send a message to the target.
//     pub fn send(&self, data: &[u8]) {
//         log::debug!("send a udp message to {}", self.remote);

//         let data = vec![0u8; UDP_LEN + IP_LEN + ETH_LEN + data.len()];

//         // convert data ptr to the ref needed.
//         let mut data_ptr_iter = UnsafeRefIter::new(&data);
//         let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
//         let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
//         let udp_header = unsafe { data_ptr_iter.next_mut::<UDP>() }.unwrap();
//         let udp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };

//         eth_header.rtype = ETH_RTYPE_IP.to_be();
//         // eth_header.shost = self.source_mac.to_bytes();
//         // eth_header.dhost = self.dest_mac.to_bytes();
//         eth_header.shost = get_mac_address(self.source.ip())
//             .map(|x| x.to_bytes())
//             .unwrap_or(BROADCAST_MAC);
//         eth_header.dhost = get_mac_address(self.remote.ip())
//             .map(|x| x.to_bytes())
//             .unwrap_or(BROADCAST_MAC);

//         ip_header.pro = IP_PROTOCAL_UDP.to_be();
//         ip_header.off = 0;
//         // ip_header.src = self.source_ip.to_u32().to_be();
//         // ip_header.dst = self.dest_ip.to_u32().to_be();
//         // ip_header.src = self.source_ip.to_u32().to_be();
//         // ip_header.dst = self.dest_ip.to_u32().to_be();
//         ip_header.tos = 0; // type of service, use 0 as default
//         ip_header.id = 0; // packet identified, use 0 as default
//         ip_header.ttl = 100; // packet ttl, use 32 as default
//         ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
//         ip_header.len = ((data.len() + UDP_LEN + IP_LEN) as u16).to_be(); // toal len
//         ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum

//         udp_header.sport = self.source.port().to_be();
//         udp_header.dport = self.remote.port().to_be();
//         udp_header.sum = 0; // udp checksum   zero means no checksum is provided.
//         udp_header.ulen = ((data.len() + UDP_LEN) as u16).to_be();

//         udp_data.copy_from_slice(&data);

//         // try to send the Message.
//         // data
//     }
//     /// receive a message from the source.
//     pub fn receive(&self) -> Option<Vec<u8>> {
//         todo!()
//     }
//     /// this function is called when the interrupt occurs.
//     pub fn interrupt(&self, data: &[u8]) {
//         self.datas.lock().push(data.to_vec())
//     }
// }

// impl Drop for UdpConnection {
//     fn drop(&mut self) {
//         if let Some(server) = self.server.upgrade() {
//             server.clients.lock().retain(|c| c.source != self.source);
//         }
//     }
// }
