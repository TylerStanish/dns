use std::net::UdpSocket;
use serialization::{FromBytes, ToBytes};
use ttl_cache::TtlCache;

mod answer;
mod cache;
mod client;
mod header;
mod packet;
mod query;
mod resolvers;
mod serialization;

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:53").expect("Could not create server");
    let mut cache = TtlCache::<query::DnsQuery, answer::DnsAnswer>::new(1024);
    let client = client::DnsClient::new(&resolvers::default_resolver, &mut cache);
    loop {
        let mut buf = [0; 1024];
        let (nread, src) = sock.recv_from(&mut buf).unwrap();
        let result = match packet::DnsPacket::from_bytes(&mut buf[..nread]) {
            Ok((packet, _)) => client.results(packet),
            Err(packet) => {
                let mut packet = packet::DnsPacket::new();
                packet.header.response_code = header::ResponseCode::FormatError;
                packet
            }
        };
        sock.send_to(&result.to_bytes(), &src).unwrap();
    }
}