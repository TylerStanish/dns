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

fn stub_resolver(host: &str, req: packet::DnsPacket) -> packet::DnsPacket {
    let mut res = packet::DnsPacket::new();
    res.header = req.header;
    res.answers = vec![];
    res
}

fn default_resolver(host: &str, req: packet::DnsPacket) -> packet::DnsPacket {
    let socket = UdpSocket::bind((host, 45678)).expect("Could not initialize listening port, is the port already taken?");
    socket.send_to(&req.to_bytes(), (host, 53)).unwrap();
    let mut res = [0; 1024];
    socket.recv_from(&mut res).unwrap();
    packet::DnsPacket::from_bytes(&mut res)
}

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:4567").expect("Could not create server");
    let mut cache = TtlCache::<query::DnsQuery, answer::DnsAnswer>::new(1024);
    let client = client::DnsClient::new(&default_resolver, &mut cache);
    loop {
        let mut buf = [0; 1024];
        let nread = sock.recv(&mut buf).unwrap();
        let packet = packet::DnsPacket::from_bytes(&mut buf[..nread]);
        let result = client.results(packet);
        sock.send(&result.to_bytes()).unwrap();
    }
}