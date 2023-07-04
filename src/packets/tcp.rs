use core::net::Ipv4Addr;

use crate::net::TcpFlags;
use crate::MacAddress;

#[derive(Debug, Clone, Copy)]
pub struct TCPPacket<'a> {
    pub source_ip: Ipv4Addr,
    pub source_mac: MacAddress,
    pub source_port: u16,
    pub dest_ip: Ipv4Addr,
    pub dest_mac: MacAddress,
    pub dest_port: u16,
    pub data_len: usize,

    pub seq: u32,        // sequence number
    pub ack: u32,        // acknowledgement number
    pub flags: TcpFlags, // flags, last 6 are flags(U, A, P, R, S, F)
    pub win: u16,        // window size
    pub urg: u16,        // urgent pointer
    pub data: &'a [u8],  // data buffer
}

// impl<'a> TCPPacket<'a> {
//     pub fn build_data(&self) -> Vec<u8> {
//         let data = vec![0u8; TCP_LEN + IP_LEN + ETH_LEN + self.data_len];

//         // convert data ptr to the ref needed.
//         let mut data_ptr_iter = UnsafeRefIter::new(&data);
//         let eth_header = unsafe { data_ptr_iter.next_mut::<Eth>() }.unwrap();
//         let ip_header = unsafe { data_ptr_iter.next_mut::<Ip>() }.unwrap();
//         let tcp_header = unsafe { data_ptr_iter.next_mut::<TCP>() }.unwrap();
//         let tcp_data = unsafe { data_ptr_iter.get_curr_arr_mut() };

//         eth_header.rtype = ETH_RTYPE_IP.to_be();
//         eth_header.shost = self.source_mac.to_bytes();
//         eth_header.dhost = self.dest_mac.to_bytes();

//         ip_header.pro = IP_PROTOCAL_TCP.to_be();
//         ip_header.off = 0;
//         ip_header.src = self.source_ip.to_u32().to_be();
//         ip_header.dst = self.dest_ip.to_u32().to_be();
//         ip_header.tos = 0; // type of service, use 0 as default
//         ip_header.id = 0; // packet identified, use 0 as default
//         ip_header.ttl = 100; // packet ttl, use 32 as default
//         ip_header.vhl = IP_HEADER_VHL; // version << 4 | header length >> 2
//         ip_header.len = ((self.data_len + TCP_LEN + IP_LEN) as u16).to_be(); // toal len
//         ip_header.sum = check_sum(ip_header as *mut Ip as *mut u8, IP_LEN as _, 0); // checksum

//         tcp_header.sport = self.source_port.to_be();
//         tcp_header.dport = self.dest_port.to_be();
//         tcp_header.offset = 5 << 4;
//         tcp_header.seq = self.seq.to_be();
//         tcp_header.ack = self.ack.to_be();
//         tcp_header.flags = self.flags;
//         tcp_header.win = 65535_u16.to_be();
//         tcp_header.urg = 0;
//         tcp_header.sum = 0;
//         tcp_data.copy_from_slice(&self.data);

//         let mut sum = self.source_ip.to_u32().to_be();
//         sum += self.dest_ip.to_u32().to_be();
//         sum += (IP_PROTOCAL_TCP as u16).to_be() as u32;
//         sum += ((self.data_len + TCP_LEN) as u16).to_be() as u32;
//         tcp_header.sum = check_sum(
//             tcp_header as *mut _ as *mut u8,
//             (TCP_LEN + self.data_len) as _,
//             sum,
//         ); // tcp checksum. zero means no checksum is provided.

//         data
//     }

//     pub fn reply(&self, data: &'a [u8]) -> Self {
//         let mut ack_packet = self.ack();
//         ack_packet.data_len += data.len();
//         ack_packet.data = data;
//         ack_packet
//     }

//     pub fn ack(&self) -> Self {
//         let mut ack = self.seq + self.data_len as u32;

//         // according to rfc793, the SYN consume one byte in the stream.
//         if self.flags.contains(TcpFlags::S) || self.flags.contains(TcpFlags::F) {
//             ack += 1;
//         }

//         let mut flags = self.flags;

//         if flags.contains(TcpFlags::R) {
//             flags.remove(TcpFlags::R);
//         }

//         Self {
//             source_ip: self.dest_ip,
//             source_mac: self.dest_mac,
//             source_port: self.dest_port,
//             dest_ip: self.source_ip,
//             dest_mac: self.source_mac,
//             dest_port: self.source_port,
//             data_len: 0,
//             seq: self.ack,
//             ack,
//             flags,
//             win: self.win,
//             urg: self.urg,
//             data: TCP_EMPTY_DATA,
//         }
//     }

//     pub fn close(&self) -> Self {
//         Self {
//             source_ip: self.dest_ip,
//             source_mac: self.dest_mac,
//             source_port: self.dest_port,
//             dest_ip: self.source_ip,
//             dest_mac: self.source_mac,
//             dest_port: self.source_port,
//             data_len: 0,
//             seq: self.ack,
//             ack: self.seq + 1,
//             flags: TcpFlags::F,
//             win: self.win,
//             urg: self.urg,
//             data: TCP_EMPTY_DATA,
//         }
//     }
// }
