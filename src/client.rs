use std::net::UdpSocket;
use crate::packet::DnsPacket;
use crate::serialization::{FromBytes, ToBytes};


pub fn lookup(host: &str, req: DnsPacket) -> DnsPacket {
    let socket = UdpSocket::bind((host, 45678)).expect("Could not initialize listening port, is the port already taken?");
    socket.send_to(&req.to_bytes(), (host, 53)).unwrap();
    let mut res = [0; 1024];
    socket.recv_from(&mut res).unwrap();
    DnsPacket::from_bytes(&mut res)
}