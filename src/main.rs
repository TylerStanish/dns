use std::net::UdpSocket;
use serialization::{FromBytes, ToBytes};
use ttl_cache::TtlCache;

mod answer;
mod cache;
mod client;
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
        let mut cache = TtlCache::<query::DnsQuery, answer::DnsAnswer>::new(1024);
        let result = packet.results(&mut cache);
        sock.send(&result.to_bytes()).unwrap();
    }
}