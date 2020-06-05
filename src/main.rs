use std::collections::HashMap;
use std::net::UdpSocket;
use serialization::{FromBytes, ToBytes};

mod answer;
mod header;
mod packet;
mod query;
mod serialization;

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:4567").expect("Could not create server");
    loop {
        let mut buf = [0; 1024];
        let nread = sock.recv(&mut buf).unwrap();
        let packet = packet::DnsPacket::from_bytes(&mut buf[..nread]);
        let result = packet.results(HashMap::new());
        sock.send(&result.to_bytes()).unwrap();
    }
}