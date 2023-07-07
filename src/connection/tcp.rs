use core::marker::PhantomData;
use core::net::SocketAddrV4;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use crate::arp_table::get_mac_address;
use crate::consts::{EthRtype, IpProtocal, BROADCAST_MAC, IP_HEADER_VHL};
use crate::net::{Eth, Ip, ETH_LEN, IP_LEN, TCP, TCP_LEN};
use crate::net_trait::NetInterface;
use crate::utils::{check_sum, UnsafeRefIter};
use crate::TcpFlags;

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

    pub fn add_queue(&self, remote: SocketAddrV4, seq: u32) {
        debug!("seq: {:?}", seq);
        let conn = Arc::new(TcpConnection {
            local: self.source.clone(),
            remote: RwLock::new(remote),
            net: PhantomData,
            options: Mutex::new(TcpSeq {
                seq: 0,
                ack: seq + 1,
                window: 65535,
                urg: 0,
            }),
            status: RwLock::new(TcpStatus::WaitingForConnect),
            datas: Mutex::new(VecDeque::new()),
            remote_closed: RwLock::new(false)
        });
        self.wait_queue.lock().push_back(conn);
    }

    pub fn get_client(&self, remote: SocketAddrV4) -> Option<Arc<TcpConnection<T>>> {
        self.clients
            .lock()
            .iter()
            .find(|x| *x.remote.read() == remote)
            .cloned()
    }
}

#[derive(Debug)]
pub struct TcpSeq {
    seq: u32,
    ack: u32,
    window: u16,
    urg: u16, // default value is 0
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpStatus {
    Unconnected,
    WaitingForSynAck,
    WaitingForConnect,
    WaitingForAck,
    WaitingForData,
    WaitingForFin,
    WaitingForFinAck,
    Closed,
}

#[derive(Debug)]
pub struct TcpConnection<T: NetInterface> {
    pub local: SocketAddrV4,
    pub remote: RwLock<SocketAddrV4>,
    pub net: PhantomData<T>,
    pub options: Mutex<TcpSeq>,
    pub status: RwLock<TcpStatus>,
    pub datas: Mutex<VecDeque<Vec<u8>>>,
    pub remote_closed: RwLock<bool>,
}

impl<T: NetInterface> TcpConnection<T> {
    /// this function will be called when need to connect to the remote endpoint.
    pub fn connect(&self, remote: SocketAddrV4) {
        *self.remote.write() = remote;
        *self.status.write() = TcpStatus::Unconnected;
        let mut options = self.options.lock();
        options.seq = 0;
        options.ack = 0;
        drop(options);
        self.send_data(&[], TcpFlags::S);
    }

    /// this function will be called when just need to send some data to the remote.
    pub fn send(&self, buf: &[u8]) -> usize {
        self.send_data(buf, TcpFlags::A | TcpFlags::P);
        buf.len()
    }

    /// this funciton will send data with tcp flags to the remote endpoint.
    /// TIPS: This is a base function in this implementation.
    pub fn send_data(&self, buf: &[u8], flags: TcpFlags) {
        let remote = self.remote.read();
        let mut options = self.options.lock();

        let data = vec![0u8; TCP_LEN + IP_LEN + ETH_LEN + buf.len()];
        // convert data ptr to the ref needed.
        let mut data_ptr_iter = UnsafeRefIter::new(&data);
        let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
        let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
        let tcp_header = unsafe { data_ptr_iter.next_mut::<TCP>() }.unwrap();
        let tcp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };
        eth_header.rtype = EthRtype::IP;
        eth_header.shost = T::local_mac_address();
        eth_header.dhost = get_mac_address(&remote.ip()).unwrap_or(BROADCAST_MAC);
        ip_header.pro = IpProtocal::TCP;
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
        tcp_header.flags = flags;
        tcp_header.win = options.window.to_be();
        tcp_header.urg = options.urg;
        tcp_header.sum = 0;
        tcp_data.copy_from_slice(buf);
        let mut sum = self
            .local
            .ip()
            .octets()
            .iter()
            .rev()
            .fold(0, |acc, x| acc << 8 | *x as u32);
        sum += remote
            .ip()
            .octets()
            .iter()
            .rev()
            .fold(0, |acc, x| acc << 8 | *x as u32);
        sum += (IpProtocal::TCP as u16).to_be() as u32;
        sum += ((buf.len() + TCP_LEN) as u16).to_be() as u32;
        // tcp checksum. zero means no checksum is provided.
        tcp_header.sum = check_sum(
            tcp_header as *mut _ as *mut u8,
            (TCP_LEN + buf.len()) as _,
            sum,
        );

        options.seq += buf.len() as u32;

        // according to rfc793, the SYN consume one byte in the stream.
        if flags.contains(TcpFlags::S) || flags.contains(TcpFlags::F) {
            options.seq += 1;
        }
        T::send(&data);

        let status = self.status.read().clone();
        if flags.contains(TcpFlags::F) {
            *self.status.write() = TcpStatus::WaitingForFinAck;
        }
        if flags.contains(TcpFlags::S) && (status == TcpStatus::Unconnected || status == TcpStatus::Closed)  {
            *self.status.write() = TcpStatus::WaitingForFinAck;
        }
    }

    /// this funciton will be called when need receive a packet from the network.
    pub fn syn_ack(&self) {
        self.send_data(&[], TcpFlags::S | TcpFlags::A);
        *self.status.write() = TcpStatus::WaitingForData;
    }

    /// this function will be called when the interrupt triggers and gets this socket throuth the net server.
    pub fn interrupt(&self, data: &[u8], seq: u32, ack: u32, flags: TcpFlags) {
        let status = self.status.read().clone();

        // tcp socket closed.
        if flags == TcpFlags::A && status == TcpStatus::WaitingForSynAck {
            *self.status.write() = TcpStatus::WaitingForData;
        }

        // tcp socket closed.
        if flags == TcpFlags::A && status == TcpStatus::WaitingForFinAck {
            *self.status.write() = TcpStatus::Closed;
            return;
        }

        // if just a reply packet, do nothing
        if flags == TcpFlags::A && data.len() == 0 {
            return;
        }

        if flags.contains(TcpFlags::F) {
            let mut options = self.options.lock();
            options.seq = ack;
            options.ack = seq + 1;
            drop(options);
            *self.remote_closed.write() = true;
            self.send_data(&[], TcpFlags::A);
            if status != TcpStatus::Closed {
                self.send_data(&[], TcpFlags::F | TcpFlags::A);
            }
            return;
        }

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
                drop(options);
                self.send_data(&[], TcpFlags::A);
            }
            TcpStatus::WaitingForSynAck => {
                if flags == TcpFlags::A {
                    *self.status.write() = TcpStatus::WaitingForData;
                }
            }
            TcpStatus::WaitingForFinAck => {
                if flags == TcpFlags::A {
                    *self.status.write() = TcpStatus::Closed;
                }
            }
            _ => {
                warn!("can't receive data from the interrupt stream.")
            }
        }
    }

    /// this function is called when need to close the socket.
    pub fn close(&self) {
        if *self.status.read() == TcpStatus::Closed || *self.remote_closed.read() {
            return;
        }
        self.send_data(&[], TcpFlags::F | TcpFlags::A);
    }

    /// return the socket status. judge whether the socket is closed.
    pub fn is_closed(&self) -> bool {
        *self.status.read() == TcpStatus::Closed && *self.remote_closed.read() == true
    }
}
