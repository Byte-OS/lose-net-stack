use core::{fmt::Debug, net::SocketAddrV4};

use alloc::{sync::Arc, vec::Vec};

use crate::{connection::SocketType, results::NetServerError, MacAddress};

pub trait NetInterface: Debug {
    fn send(data: &[u8]);
    fn local_mac_address() -> MacAddress;
}

pub trait SocketInterface {
    fn sendto(&self, _data: &[u8], _remote: Option<SocketAddrV4>) -> Result<usize, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn recv_from(&self) -> Result<(Vec<u8>, SocketAddrV4), NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn bind(self: Arc<Self>, _local: SocketAddrV4) -> Result<(), NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn listen(self: Arc<Self>) -> Result<(), NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn connect(self: Arc<Self>, _remote: SocketAddrV4) -> Result<(), NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn accept(&self) -> Result<Arc<dyn SocketInterface>, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn readable(&self) -> Result<bool, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn get_local(&self) -> Result<SocketAddrV4, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn get_protocol(&self) -> Result<SocketType, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn get_remote(&self) -> Result<SocketAddrV4, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn is_closed(&self) -> Result<bool, NetServerError> {
        Err(NetServerError::Unsupported)
    }
    fn close(&self) -> Result<(), NetServerError> {
        Err(NetServerError::Unsupported)
    }
}
