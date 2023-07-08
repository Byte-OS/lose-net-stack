use core::{marker::PhantomData, net::SocketAddrV4};

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Weak,
    vec::Vec,
};
use spin::Mutex;

use crate::{
    arp_table::get_mac_address,
    consts::{EthRtype, IpProtocal, BROADCAST_MAC, IP_HEADER_VHL},
    net::{Eth, Ip, ETH_LEN, IP_LEN, UDP, UDP_LEN},
    net_trait::{NetInterface, SocketInterface},
    results::NetServerError,
    utils::{check_sum, UnsafeRefIter},
    MacAddress,
};

use super::{NetServer, SocketType};

pub struct UdpServerInner {
    pub local: SocketAddrV4,
    pub remote: Option<SocketAddrV4>,
    pub packets: BTreeMap<SocketAddrV4, VecDeque<Vec<u8>>>,
}

/// Udp server.
pub struct UdpServer<T: NetInterface> {
    pub inner: Mutex<UdpServerInner>,
    pub server: Weak<NetServer<T>>,
    pub net: PhantomData<T>,
}

impl<T: NetInterface> UdpServer<T> {
    pub const fn new(server: Weak<NetServer<T>>, local: SocketAddrV4) -> Self {
        Self {
            inner: Mutex::new(UdpServerInner {
                local,
                remote: None,
                packets: BTreeMap::new(),
            }),
            server,
            net: PhantomData,
        }
    }

    pub fn add_queue(&self, addr: SocketAddrV4, data: &[u8]) {
        debug!("receive a udp message ({} bytes) from {}", data.len(), addr);
        let mut inner = self.inner.lock();
        if !inner.packets.contains_key(&addr) {
            inner.packets.insert(addr, VecDeque::new());
        }
        inner
            .packets
            .get_mut(&addr)
            .unwrap()
            .push_back(data.to_vec());
    }
}

impl<T: NetInterface> SocketInterface for UdpServer<T> {
    fn recv_from(&self, remote: Option<SocketAddrV4>) -> Result<Vec<u8>, NetServerError> {
        let mut inner = self.inner.lock();
        let addr = remote.or(inner.remote);
        if addr.is_none() {
            return Err(NetServerError::NoUdpRemoteAddress);
        }
        let addr = addr.unwrap();
        inner
            .packets
            .get_mut(&addr)
            .map_or(Err(NetServerError::EmptyData), |x| {
                x.pop_front().ok_or(NetServerError::EmptyData)
            })
    }

    fn sendto(&self, buf: &[u8], remote: Option<SocketAddrV4>) -> Result<usize, NetServerError> {
        let inner = self.inner.lock();
        let addr = remote.or(inner.remote);
        if addr.is_none() {
            return Err(NetServerError::NoUdpRemoteAddress);
        }
        let addr = addr.unwrap();

        log::debug!("send a udp message({} bytes) to {}", buf.len(), addr);

        if addr.ip().is_loopback() || addr.ip() == inner.local.ip() {
            let port = addr.port();
            if let Some(server) = self.server.upgrade() {
                server.get_udp(&port).map(|x| x.add_queue(inner.local, buf));
            }
            return Ok(buf.len());
        }

        let data = vec![0u8; UDP_LEN + IP_LEN + ETH_LEN + buf.len()];

        // convert data ptr to the ref needed.
        let mut data_ptr_iter = UnsafeRefIter::new(&data);
        let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
        let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
        let udp_header = unsafe { data_ptr_iter.next_mut::<UDP>() }.unwrap();
        let udp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };

        eth_header.rtype = EthRtype::IP.into();
        eth_header.shost = MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        eth_header.dhost = BROADCAST_MAC;
        eth_header.shost = get_mac_address(inner.local.ip()).unwrap_or(BROADCAST_MAC);
        eth_header.dhost = get_mac_address(addr.ip()).unwrap_or(BROADCAST_MAC);

        ip_header.pro = IpProtocal::UDP.into();
        ip_header.off = 0;
        ip_header.src = inner.local.ip().clone();
        ip_header.dst = addr.ip().clone();
        ip_header.tos = 0; // type of service, use 0 as default
        ip_header.id = 0; // packet identified, use 0 as default
        ip_header.ttl = 100; // packet ttl, use 32 as default
        ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
        ip_header.len = ((buf.len() + UDP_LEN + IP_LEN) as u16).to_be(); // toal len
        ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum

        udp_header.sport = inner.local.port().to_be();
        udp_header.dport = addr.port().to_be();
        udp_header.sum = 0; // udp checksum   zero means no checksum is provided.
        udp_header.ulen = ((buf.len() + UDP_LEN) as u16).to_be();

        udp_data.copy_from_slice(&buf);

        T::send(&data);

        Ok(buf.len())
    }

    fn get_local(&self) -> Result<SocketAddrV4, NetServerError> {
        Ok(self.inner.lock().local)
    }

    fn get_protocol(&self) -> Result<SocketType, NetServerError> {
        Ok(SocketType::UDP)
    }

    fn bind(&self, local: SocketAddrV4) -> Result<(), NetServerError> {
        match self.server.upgrade() {
            Some(net_server) => {
                let mut inner = self.inner.lock();
                // check whether the target port was already assigned.
                if net_server.udp_is_used(local.port()) {
                    return Err(NetServerError::PortWasUsed);
                }
                // check whether the udp server was binded. if binded then drop the port.
                if let Some(_) = net_server.get_udp(&inner.local.port()) {
                    net_server.remote_udp(&inner.local.port());
                }
                inner.local = local;
                Ok(())
            }
            None => Err(NetServerError::ServerNotExists),
        }
    }

    fn close(&self) -> Result<(), NetServerError> {
        match self.server.upgrade() {
            Some(net_server) => {
                let inner = self.inner.lock();
                // check whether the target port was already assigned.
                if let Some(_) = net_server.get_udp(&inner.local.port()) {
                    net_server.remote_udp(&inner.local.port());
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
