use core::net::{Ipv4Addr, SocketAddrV4};
use core::ptr::NonNull;

use alloc::sync::Arc;
use lose_net_stack::connection::NetServer;
use lose_net_stack::net_trait::{NetInterface, SocketInterface};

use lose_net_stack::MacAddress;
use opensbi_rt::{print, println};
use spin::Mutex;
use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

use crate::virtio_impls::HalImpl;

pub struct NetDevice(VirtIONet<HalImpl, MmioTransport>);

unsafe impl Sync for NetDevice {}
unsafe impl Send for NetDevice {}

impl NetDevice {
    pub fn new(ptr: usize) -> Self {
        Self(
            VirtIONet::<HalImpl, MmioTransport>::new(unsafe {
                MmioTransport::new(NonNull::new(ptr as *mut VirtIOHeader).unwrap())
                    .expect("failed to create net driver")
            })
            .expect("failed to create net driver"),
        )
    }

    #[allow(dead_code)]
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        self.0.recv(buf).expect("can't receive data")
    }

    pub fn send(&mut self, buf: &[u8]) {
        debug!("send data {} bytes", buf.len());
        hexdump(buf);
        self.0.send(buf).expect("can't receive data")
    }
}

#[derive(Debug)]
pub struct NetMod;

impl NetInterface for NetMod {
    fn send(data: &[u8]) {
        NET.lock().as_mut().unwrap().send(data);
    }

    fn local_mac_address() -> MacAddress {
        MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    }
}

pub static NET: Mutex<Option<NetDevice>> = Mutex::new(None);

pub fn test_udp_local(net_server: &Arc<NetServer<NetMod>>) {
    let server = net_server.blank_udp();
    server
        .clone()
        .bind(SocketAddrV4::new(net_server.get_local_ip(), 17001))
        .expect("can't bind ip to server");
    let client = net_server.blank_udp();
    client
        .clone()
        .bind(SocketAddrV4::new(net_server.get_local_ip(), 0))
        .expect("can't bind ip to client");
    client
        .sendto(b"Hello Server!", Some(server.get_local().unwrap()))
        .expect("can't send to udp server");
    assert_eq!(
        server
            .recv_from()
            .expect("cant receive data from client")
            .0,
        b"Hello Server!"
    );
    server
        .sendto(b"Hello Client!", Some(client.get_local().unwrap()))
        .expect("can't send to udp server");
    assert_eq!(
        client
            .recv_from()
            .expect("cant receive data from server")
            .0,
        b"Hello Client!"
    )
}

pub fn test_tcp_local(net_server: &Arc<NetServer<NetMod>>) {
    let tcp_server = net_server.blank_tcp();
    tcp_server
        .clone()
        .bind(SocketAddrV4::new(net_server.get_local_ip(), 6202))
        .expect("can't bind ip to server");
    let client = net_server.blank_tcp();
    client
        .clone()
        .bind(SocketAddrV4::new(net_server.get_local_ip(), 0))
        .expect("can't bind ip to client");

    client
        .clone()
        .connect(tcp_server.get_local().unwrap())
        .expect("can't connect to tcp server");
    let server_client = tcp_server.accept().expect("can't receive a clint");
    client
        .sendto(b"Hello server", None)
        .expect("cant send data to server");
    assert_eq!(server_client.recv_from().unwrap().0, b"Hello server");
    server_client.sendto(b"Hello client", None).unwrap();
    assert_eq!(client.recv_from().unwrap().0, b"Hello client");

    client.close().unwrap();

    assert!(server_client.is_closed().unwrap() == true);
    assert!(client.is_closed().unwrap() == true);
}

pub fn init() {
    // let mut net = NetDevice::new(0x1000_8000);
    *NET.lock() = Some(NetDevice::new(0x1000_8000));
    let net_server = Arc::new(NetServer::<NetMod>::new(
        MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
        Ipv4Addr::new(10, 0, 2, 15),
    ));

    test_udp_local(&net_server);
    test_tcp_local(&net_server);

    info!("net stack example test successed!");
}

#[no_mangle]
pub fn hexdump(data: &[u8]) {
    const PRELAND_WIDTH: usize = 70;
    println!("{:-^1$}", " hexdump ", PRELAND_WIDTH);
    for offset in (0..data.len()).step_by(16) {
        for i in 0..16 {
            if offset + i < data.len() {
                print!("{:02x} ", data[offset + i]);
            } else {
                print!("{:02} ", "");
            }
        }

        print!("{:>6}", ' ');

        for i in 0..16 {
            if offset + i < data.len() {
                let c = data[offset + i];
                if c >= 0x20 && c <= 0x7e {
                    print!("{}", c as char);
                } else {
                    print!(".");
                }
            } else {
                print!("{:02} ", "");
            }
        }

        println!("");
    }
    println!("{:-^1$}", " hexdump end ", PRELAND_WIDTH);
}

// handle packet when receive a tcp packet
// pub fn receive_tcp(net: &mut VirtIONet<HalImpl, MmioTransport>, tcp_packet: &TCPPacket) {
//     const CONTENT: &str = include_str!("../index.html");
//     let header = format!(
//         "\
// HTTP/1.1 200 OK\r\n\
// Content-Type: text/html\r\n\
// Content-Length: {}\r\n\
// Connecion: keep-alive\r\n\
// \r\n\
// {}",
//         CONTENT.len(),
//         CONTENT
//     );

//     // is it a get request?
//     if tcp_packet.data_len > 10 && tcp_packet.data[..4] == [0x47, 0x45, 0x54, 0x20] {
//         let mut index = 0;
//         for i in 4..tcp_packet.data_len {
//             if tcp_packet.data[i] == 0x20 {
//                 index = i;
//                 break;
//             }
//         }

//         let url = String::from_utf8_lossy(&tcp_packet.data[4..index]);
//         info!("request for {}", url);
//         if url == "/close" {
//             let reply_packet = tcp_packet.ack();
//             net.send(&reply_packet.build_data())
//                 .expect("can't send reply packet");
//             sbi::legacy::shutdown();
//         }
//         let reply_packet = tcp_packet.reply(header.as_bytes());
//         net.send(&reply_packet.build_data()).expect("can't send to");
//         let mut close_packet = tcp_packet.ack();
//         close_packet.seq += reply_packet.data.len() as u32;
//         close_packet.flags = TcpFlags::F;
//         net.send(&close_packet.build_data())
//             .expect("can't send close packet");
//     } else {
//         if tcp_packet.data == b"this is a ping!" {
//             let mut reply_packet = tcp_packet.ack();
//             reply_packet.flags = TcpFlags::F | TcpFlags::A;
//             net.send(&reply_packet.build_data())
//                 .expect("can't send reply packet");
//         } else {
//             debug!(
//                 "tcp_packet flags:{:?}  data_len: {}",
//                 tcp_packet.flags, tcp_packet.data_len
//             );
//             if tcp_packet.flags.contains(TcpFlags::A) && tcp_packet.data_len == 0 {
//                 return;
//             }
//             let mut reply_packet = tcp_packet.ack();
//             if reply_packet.flags.contains(TcpFlags::F) {
//                 reply_packet.flags = TcpFlags::A;
//             }
//             net.send(&reply_packet.build_data())
//                 .expect("can't send reply packet");
//         }
//     }
// }
