use core::net::SocketAddr;

pub struct TcpServer {
    pub source: SocketAddr,
    pub target: SocketAddr,
}
