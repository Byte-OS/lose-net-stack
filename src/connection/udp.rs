use core::net::SocketAddr;

pub struct UdpServer {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub handler: fn(client: &mut UdpServer, data: &[u8]), // udp server handler, can be used when the data was received.
}
