use core::net::Ipv4Addr;
use core::ptr::NonNull;

use alloc::sync::Arc;
use alloc::vec;
use lose_net_stack::connection::NetServer;
use lose_net_stack::net_trait::NetInterface;

use lose_net_stack::MacAddress;
use opensbi_rt::{print, println};
use spin::Mutex;
// use virtio_drivers::{VirtIONet, VirtIOHeader, MmioTransport};
use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

use crate::virtio_impls::HalImpl;

// pub static NET: Mutex<VirtIONet<HalImpl, MmioTransport>> = Mutex::new();

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

    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        self.0.recv(buf).expect("can't receive data")
    }

    pub fn send(&mut self, buf: &[u8]) {
        debug!("send data {} bytes", buf.len());
        hexdump(buf);
        self.0.send(buf).expect("can't receive data")
    }
}

pub struct NetMod;

impl NetInterface for NetMod {
    fn send(data: &[u8]) {
        debug!("send data {} bytes", data.len());
        hexdump(data);
        NET.lock().as_mut().unwrap().send(data);
    }
}

pub static NET: Mutex<Option<NetDevice>> = Mutex::new(None);
// pub static NET_SERVER: Mutex<NetServer<NetMod>> = Mutex::new(NetServer::new(
//     MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
//     Ipv4Addr::new(10, 0, 2, 15),
// ));

pub fn init() {
    // let mut net = NetDevice::new(0x1000_8000);
    *NET.lock() = Some(NetDevice::new(0x1000_8000));
    let net_server = Arc::new(NetServer::<NetMod>::new(
        MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
        Ipv4Addr::new(10, 0, 2, 15),
    ));

    let udp_server = net_server.listen_udp(2000).expect("can't listen udp");
    // udp_server.sendto(
    //     SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 2000),
    //     b"Hello world!",
    // );
    loop {
        info!("waiting for data");

        if let Some(udp_packet) = udp_server.receve_from() {
            udp_server.sendto(udp_packet.addr, b"reply");
            break;
        }

        let mut buf = vec![0u8; 1024];
        let len = NET.lock().as_mut().unwrap().recv(&mut buf);
        info!("receive {len} bytes from net");
        hexdump(&buf[..len]);
        net_server.analysis_net_data(&buf[..len]);

        // info!("packet: {:?}", packet);
    }

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
