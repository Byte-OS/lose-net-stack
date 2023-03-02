
use core::ptr::NonNull;

use alloc::format;
use alloc::{vec, string::String};
use alloc::vec::Vec;
use lose_net_stack::{LoseStack, IPv4, MacAddress, results::Packet, TcpFlags};
use opensbi_rt::{print, println};
// use virtio_drivers::{VirtIONet, VirtIOHeader, MmioTransport};
use virtio_drivers::device::net::VirtIONet;
use virtio_drivers::transport::mmio::{MmioTransport, VirtIOHeader};

use crate::virtio_impls::HalImpl;

pub fn init() {
    let mut net = VirtIONet::<HalImpl, MmioTransport>::new(unsafe {
        MmioTransport::new(NonNull::new(0x1000_8000 as *mut VirtIOHeader).unwrap()).expect("failed to create net driver")
    }).expect("failed to create net driver");

    let lose_stack = LoseStack::new(IPv4::new(10, 0, 2, 15), MacAddress::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));

    loop {
        info!("waiting for data");
        let mut buf = vec![0u8; 1024];
        let len = net.recv(&mut buf).expect("can't receive data");

        info!("receive {len} bytes from net");
        hexdump(&buf[..len]);

        let packet = lose_stack.analysis(&buf[..len]);
        info!("packet: {:?}", packet);

        match packet {
            Packet::ARP(arp_packet) => {
                let reply_packet = arp_packet.reply_packet(lose_stack.ip, lose_stack.mac).expect("can't build reply");
                net.send(&reply_packet.build_data()).expect("can't send net data");
            },
            Packet::UDP(udp_packet) => {
                info!("{}:{}(MAC:{}) -> {}:{}(MAC:{})  len:{}", udp_packet.source_ip, udp_packet.source_port, udp_packet.source_mac, 
                    udp_packet.dest_ip, udp_packet.dest_port, udp_packet.dest_mac, udp_packet.data_len);
                info!("data: {}", String::from_utf8_lossy(udp_packet.data.as_ref()));
                hexdump(udp_packet.data.as_ref());

                if String::from_utf8_lossy(udp_packet.data.as_ref()) == "this is a ping!" {
                    let data = r"reply".as_bytes();
                    let udp_reply_packet = udp_packet.reply(data);
                    net.send(&udp_reply_packet.build_data()).expect("can't send using net dev");
                    break;
                }
            }
            Packet::TCP(tcp_packet) => {
                if tcp_packet.flags == TcpFlags::S {
                    let mut reply_packet = tcp_packet.ack();
                    reply_packet.flags = TcpFlags::S | TcpFlags::A;
                    let reply_data = &reply_packet.build_data();
                    net.send(&reply_data).expect("can't send to net");
                } else if tcp_packet.flags.contains(TcpFlags::F) {
                    let mut reply_packet = tcp_packet.ack();
                    net.send(&reply_packet.build_data()).expect("can't send to net");

                    let mut end_packet = reply_packet.ack();
                    end_packet.flags |= TcpFlags::F;
                    net.send(&end_packet.build_data()).expect("can't send to net");
                } else {
                    info!("{}:{}(MAC:{}) -> {}:{}(MAC:{})  len:{}", tcp_packet.source_ip, tcp_packet.source_port, tcp_packet.source_mac, 
                    tcp_packet.dest_ip, tcp_packet.dest_port, tcp_packet.dest_mac, tcp_packet.data_len);
                    info!("data: {}", String::from_utf8_lossy(tcp_packet.data.as_ref()));

                    hexdump(tcp_packet.data.as_ref());
                    if tcp_packet.flags.contains(TcpFlags::A) && tcp_packet.data_len == 0 {
                        continue;
                    }
                    const CONTENT: &str = r#"<html>
                        <head>
                        <title>Hello, This is lose-net-stack</title>
                        </head>
                        <body>
                        <center>
                            <h1>Lose-Net-Stack, website: <a href='http://github.com/yfblock/lose-net-stack'>http://github.com/yfblock/lose-net-stack</a></h1>
                        </center>
                        <hr>
                        </body>
                        </html>
                    "#;
                    let header = format!("\
HTTP/1.1 200 OK\r\n\
Content-Type: text/html\r\n\
Content-Length: {}\r\n\
Connecion: close\r\n\
\r\n\
{}", CONTENT.len(), CONTENT);
                    // let reply_data = r"th".as_bytes();
                    // if String::from_utf8_lossy(tcp_packet.data.as_ref()) == "this is a ping!" {
                    //     let temp_data: Vec<u8> = Vec::new();
                    //     let mut reply_packet = tcp_packet.reply(reply_data);
                    //     reply_packet.flags = TcpFlags::A;
                    //     let reply_data = &reply_packet.build_data();
                    //     net.send(&reply_data).expect("can't send to net");
                    // }
                    let mut reply_packet = tcp_packet.reply(header.as_bytes());
                    net.send(&reply_packet.build_data()).expect("can't send to");
                }
            }
            _ => {}
        }
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

/* UDP SEND HEXDUMP
------------------------------ hexdump -------------------------------
ff ff ff ff ff ff 52 54 00 12 34 56 08 00 45 00       ......RT..4V..E.
28 00 00 00 00 00 20 11 61 ff 0a 00 02 0f 0a 00       (..... .a.......
02 02 38 18 39 18 14 00 5e ff 48 65 6c 6c 6f 20       ..8.9...^.Hello 
57 6f 72 6c 64 21                                     World!                              
---------------------------- hexdump end -----------------------------
*/