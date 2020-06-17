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

fn stub_resolver(_host: &str, req: packet::DnsPacket) -> packet::DnsPacket {
    let mut res = packet::DnsPacket::new();
    res.header = req.header;
    res.header.is_response = true;
    res.header.answers_count = 1;
    res.header.additional_count = 0;
    res.header.authority_count = 0;
    let mut answer = answer::DnsAnswer::new();
    answer.address = 0xbeefbeef;
    answer.name = req.queries[0].name.clone();
    answer.class = 1;
    answer.data_length = 4;
    answer.qtype = req.queries[0].qtype;
    res.answers = vec![answer];
    res.queries = req.queries;
    res
}

fn default_resolver(host: &str, req: packet::DnsPacket) -> packet::DnsPacket {
    let socket = UdpSocket::bind(("0.0.0.0", 4589)).expect("Could not initialize listening port, is the port already taken?");
    socket.send_to(&req.to_bytes(), (host, 53)).unwrap();
    let mut res = [0; 1024];
    socket.recv_from(&mut res).unwrap();
    let res = packet::DnsPacket::from_bytes(&mut res).0;
    println!("{:?}", res);
    res
}

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:53").expect("Could not create server");
    let mut cache = TtlCache::<query::DnsQuery, answer::DnsAnswer>::new(1024);
    let client = client::DnsClient::new(&default_resolver, &mut cache);
    loop {
        let mut buf = [0; 1024];
        let (nread, src) = sock.recv_from(&mut buf).unwrap();
        let (packet, _) = packet::DnsPacket::from_bytes(&mut buf[..nread]);
        let result = client.results(packet);
        sock.send_to(&result.to_bytes(), &src).unwrap();
    }
}