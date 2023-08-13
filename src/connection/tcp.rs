use core::marker::PhantomData;
use core::net::SocketAddrV4;

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::{Mutex, RwLock};

use crate::arp_table::get_mac_address;
use crate::consts::{EthRtype, IpProtocal, BROADCAST_MAC, IP_HEADER_VHL};
use crate::net::{Eth, Ip, ETH_LEN, IP_LEN, TCP, TCP_LEN};
use crate::net_trait::{NetInterface, SocketInterface};
use crate::results::NetServerError;
use crate::utils::{check_sum, UnsafeRefIter};
use crate::TcpFlags;

use super::{NetServer, SocketType};

pub struct TcpServer<T: NetInterface> {
    pub local: RwLock<SocketAddrV4>,
    pub clients: Mutex<Vec<Arc<TcpConnection<T>>>>,
    pub wait_queue: Mutex<VecDeque<Arc<TcpConnection<T>>>>,
    pub server: Weak<NetServer<T>>,
    pub is_client: RwLock<bool>,
}

impl<T: NetInterface> TcpServer<T> {
    pub fn add_queue(&self, remote: SocketAddrV4, seq: u32) -> Option<Arc<TcpConnection<T>>> {
        let conn = Arc::new(TcpConnection {
            local: self.local.read().clone(),
            remote: RwLock::new(remote),
            net: PhantomData,
            options: Mutex::new(TcpSeq {
                seq: 0,
                ack: seq + 1,
                window: 65535,
                urg: 0,
            }),
            status: RwLock::new(TcpStatus::Unconnected),
            datas: Mutex::new(VecDeque::new()),
            remote_closed: RwLock::new(false),
            server: self.server.clone(),
        });
        self.wait_queue.lock().push_back(conn.clone());
        Some(conn)
    }

    pub fn get_client(&self, remote: SocketAddrV4) -> Option<Arc<TcpConnection<T>>> {
        self.clients
            .lock()
            .iter()
            .find(|x| *x.remote.read() == remote)
            .cloned()
    }

    pub fn remove_client(&self, remote: SocketAddrV4) {
        self.clients.lock().retain(|x| *x.remote.read() != remote)
    }
}

impl<T: NetInterface + 'static> SocketInterface for TcpServer<T> {
    fn accept(&self) -> Result<Arc<dyn SocketInterface>, NetServerError> {
        if let Some(conn) = self.wait_queue.lock().pop_front() {
            self.clients.lock().push(conn.clone());
            if !self.get_local().unwrap().ip().is_private() {
                conn.syn_ack();
            }
            Ok(conn)
        } else {
            Err(NetServerError::EmptyClient)
        }
    }

    fn bind(self: Arc<Self>, mut local: SocketAddrV4) -> Result<(), NetServerError> {
        let mut old_local = self.local.write();
        let net_server = self
            .server
            .upgrade()
            .ok_or(NetServerError::ServerNotExists)?;
        if local.port() == 0 {
            local.set_port(net_server.alloc_tcp_port());
        }
        if local.ip().is_loopback() || local.ip().is_unspecified() {
            local.set_ip(*old_local.ip());
        }
        net_server.remote_tcp(&old_local.port());
        net_server.tcp_map.lock().insert(local.port(), self.clone());
        *old_local = local;
        Ok(())
    }

    fn connect(self: Arc<Self>, remote: SocketAddrV4) -> Result<(), NetServerError> {
        *self.is_client.write() = true;
        let remote = if remote.ip().is_loopback() || remote.ip().is_unspecified() {
            SocketAddrV4::new(*self.local.read().ip(), remote.port())
        } else {
            remote
        };
        if self.get_local().unwrap().port() == 0 {
            self.clone().bind(self.get_local().unwrap())?;
        }
        let conn = Arc::new(TcpConnection {
            local: self.local.read().clone(),
            remote: RwLock::new(remote),
            net: PhantomData,
            options: Mutex::new(TcpSeq {
                seq: 0,
                ack: 0,
                window: 65535,
                urg: 0,
            }),
            status: RwLock::new(TcpStatus::Unconnected),
            datas: Mutex::new(VecDeque::new()),
            remote_closed: RwLock::new(false),
            server: self.server.clone(),
        });
        conn.clone().connect(remote)?;
        self.clients.lock().push(conn.clone());
        Ok(())
    }

    fn get_local(&self) -> Result<SocketAddrV4, NetServerError> {
        Ok(self.local.read().clone())
    }

    fn get_protocol(&self) -> Result<SocketType, NetServerError> {
        Ok(SocketType::TCP)
    }

    fn listen(self: Arc<Self>) -> Result<(), NetServerError> {
        if self.get_local().unwrap().port() == 0 {
            self.clone().bind(self.get_local().unwrap())?;
        }
        Ok(())
    }

    fn recv_from(&self) -> Result<(Vec<u8>, SocketAddrV4), NetServerError> {
        let is_client = self.is_client.read().clone();

        if is_client {
            self.clients.lock()[0].recv_from()
        } else {
            Err(NetServerError::Unsupported)
        }
    }

    fn sendto(&self, data: &[u8], remote: Option<SocketAddrV4>) -> Result<usize, NetServerError> {
        let is_client = self.is_client.read().clone();

        if is_client {
            self.clients.lock()[0].sendto(data, remote)
        } else {
            Err(NetServerError::Unsupported)
        }
    }

    fn close(&self) -> Result<(), NetServerError> {
        let is_client = self.is_client.read().clone();

        if is_client {
            self.clients.lock()[0].close()
        } else {
            Err(NetServerError::Unsupported)
        }
    }

    fn is_closed(&self) -> Result<bool, NetServerError> {
        let is_client = self.is_client.read().clone();

        if is_client {
            self.clients.lock()[0].is_closed()
        } else {
            Ok(false)
        }
    }

    fn readable(&self) -> Result<bool, NetServerError> {
        let is_client = self.is_client.read().clone();

        if is_client {
            self.clients.lock()[0].readable()
        } else {
            Ok(self.wait_queue.lock().len() > 0)
        }
    }

    fn get_remote(&self) -> Result<SocketAddrV4, NetServerError> {
        let is_client = self.is_client.read().clone();

        if is_client {
            self.clients.lock()[0].get_remote()
        } else {
            Err(NetServerError::Unsupported)
        }
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
    WaitingForData,
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
    pub server: Weak<NetServer<T>>,
}

impl<T: NetInterface + 'static> TcpConnection<T> {
    /// this funciton will send data with tcp flags to the remote endpoint.
    /// TIPS: This is a base function in this implementation.
    pub fn send_data(&self, buf: &[u8], flags: TcpFlags) {
        let remote = self.remote.read();
        // handle loopback device.
        if remote.ip().is_loopback()
            || remote.ip().is_unspecified()
            || remote.ip() == self.get_local().unwrap().ip()
        {
            if buf.len() == 0 {
                return;
            }
            if let Some(remote_tcp) = self.server.upgrade().unwrap().get_tcp(&remote.port()) {
                remote_tcp
                    .get_client(self.get_local().unwrap())
                    .map(|x| x.add_data(buf));
                // send to local data if the target is not accepted.
                remote_tcp
                    .wait_queue
                    .lock()
                    .iter_mut()
                    .find(|x| *x.remote.read() == self.get_local().unwrap())
                    .map(|x| x.add_data(buf));
            }
            return;
        }

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
        ip_header.src = self.get_local().unwrap().ip().clone();
        ip_header.dst = *remote.ip();
        ip_header.tos = 0; // type of service, use 0 as default
        ip_header.id = 0; // packet identified, use 0 as default
        ip_header.ttl = 100; // packet ttl, use 32 as default
        ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
        ip_header.len = ((buf.len() + TCP_LEN + IP_LEN) as u16).to_be(); // toal len
        ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum
        tcp_header.sport = self.get_local().unwrap().port().to_be();
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
        if flags.contains(TcpFlags::S)
            && (status == TcpStatus::Unconnected || status == TcpStatus::Closed)
        {
            *self.status.write() = TcpStatus::WaitingForFinAck;
        }
    }

    /// this funciton will be called when need receive a packet from the network.
    pub fn syn_ack(&self) {
        self.send_data(&[], TcpFlags::S | TcpFlags::A);
        *self.status.write() = TcpStatus::WaitingForData;
    }

    /// add data to this network
    pub fn add_data(&self, data: &[u8]) {
        debug!(
            "receive a tcp message({} bytes) from {:?}",
            data.len(),
            self.remote.read()
        );
        self.datas.lock().push_back(data.to_vec());
    }

    /// this function will be called when the interrupt triggers and gets this socket throuth the net server.
    pub fn interrupt(&self, data: &[u8], seq: u32, ack: u32, flags: TcpFlags) {
        let status = self.status.read().clone();

        if self.is_closed().unwrap() {
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
                // if just a reply packet, do nothing
                if flags == TcpFlags::A && data.len() == 0 {
                    return;
                }
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
}

impl<T: NetInterface + 'static> SocketInterface for TcpConnection<T> {
    /// this function will be called when need to connect to the remote endpoint.
    fn connect(self: Arc<Self>, remote: SocketAddrV4) -> Result<(), NetServerError> {
        *self.remote.write() = remote;
        *self.status.write() = TcpStatus::Unconnected;
        let mut options = self.options.lock();
        options.seq = 0;
        options.ack = 0;
        drop(options);
        debug!(
            "the net {:?} try to connect to {:?}",
            self.get_local().unwrap(),
            remote
        );
        if remote.ip().is_loopback()
            || remote.ip().is_unspecified()
            || remote.ip() == self.get_local().unwrap().ip()
        {
            // connect to the local endpoint
            if let Some(remote_tcp) = self.server.upgrade().unwrap().get_tcp(&remote.port()) {
                debug!(
                    "add client {:?} to {:?}",
                    self.get_local().unwrap(),
                    remote_tcp.get_local().unwrap()
                );
                *self.status.write() = TcpStatus::WaitingForData;
                let remote_client = remote_tcp.add_queue(self.get_local().unwrap(), 0).unwrap();
                *remote_client.status.write() = TcpStatus::WaitingForData;
            } else {
                return Err(NetServerError::Blocking)
            }
        } else {
            self.send_data(&[], TcpFlags::S);
        }
        Ok(())
    }

    fn get_local(&self) -> Result<SocketAddrV4, NetServerError> {
        Ok(self.local)
    }

    fn get_protocol(&self) -> Result<SocketType, NetServerError> {
        Ok(SocketType::TCP)
    }

    fn recv_from(&self) -> Result<(Vec<u8>, SocketAddrV4), NetServerError> {
        self.datas
            .lock()
            .pop_front()
            .map(|x| (x, self.remote.read().clone()))
            .ok_or(NetServerError::EmptyData)
    }

    /// this function will be called when just need to sendc some data to the remote.
    fn sendto(&self, data: &[u8], _remote: Option<SocketAddrV4>) -> Result<usize, NetServerError> {
        debug!(
            "send a tcp message({} bytes) from {:?} to {:?}",
            data.len(),
            self.get_local()?,
            self.remote.read()
        );
        self.send_data(data, TcpFlags::A | TcpFlags::P);
        Ok(data.len())
    }

    /// this function is called when need to close the socket.
    fn close(&self) -> Result<(), NetServerError> {
        let remote = self.remote.read();
        // handle loopback device.
        if remote.ip().is_loopback()
            || remote.ip().is_unspecified()
            || remote.ip() == self.get_local().unwrap().ip()
        {
            if let Some(remote_tcp) = self.server.upgrade().unwrap().get_tcp(&remote.port()) {
                let remote_client = remote_tcp
                    .get_client(SocketAddrV4::new(
                        remote.ip().clone(),
                        self.get_local().unwrap().port(),
                    ))
                    .unwrap();
                *remote_client.status.write() = TcpStatus::Closed;
                *remote_client.remote_closed.write() = true;
                remote_client.datas.lock().push_back(vec![]);
                *self.status.write() = TcpStatus::Closed;
                *self.remote_closed.write() = true;
                self.datas.lock().push_back(vec![]);
            }
            return Ok(());
        }

        if *self.status.read() == TcpStatus::Closed || *self.remote_closed.read() {
            return Ok(());
        }
        self.send_data(&[], TcpFlags::F | TcpFlags::A);
        Ok(())
    }

    /// return the socket status. judge whether the socket is closed.
    fn is_closed(&self) -> Result<bool, NetServerError> {
        Ok(*self.status.read() == TcpStatus::Closed && *self.remote_closed.read() == true)
    }

    fn readable(&self) -> Result<bool, NetServerError> {
        Ok(self.datas.lock().len() > 0)
    }

    fn get_remote(&self) -> Result<SocketAddrV4, NetServerError> {
        Ok(self.remote.read().clone())
    }
}
