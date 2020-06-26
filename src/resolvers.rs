use crate::answer;
use crate::header::DnsHeader;
use crate::packet;
use crate::serialization::{FromBytes, ToBytes};
use std::net::UdpSocket;

pub fn stub_resolver(_host: &str, req: packet::DnsPacket) -> packet::DnsPacket {
    let mut res = packet::DnsPacket::new();
    res.header = req.header;
    res.header.is_response = true;
    res.header.answers_count = 1;
    res.header.additional_count = 0;
    res.header.authority_count = 0;
    let mut answer = answer::DnsAnswer::new();
    answer.rdata = vec![0xde, 0xca, 0xfb, 0xad];
    answer.name = req.queries[0].name.clone();
    answer.class = 1;
    answer.data_length = 4;
    answer.qtype = req.queries[0].qtype.clone();
    res.answers = vec![answer];
    res.queries = req.queries;
    res
}

pub fn default_resolver(host: &str, req: packet::DnsPacket) -> packet::DnsPacket {
    let socket = UdpSocket::bind(("0.0.0.0", 4589))
        .expect("Could not initialize listening port, is the port already taken?");
    socket.send_to(&req.to_bytes(), (host, 53)).unwrap();
    let mut res = [0; 1024];
    socket.recv_from(&mut res).unwrap();
    let res = match packet::DnsPacket::from_bytes(&mut res) {
        // TODO PLEASE don't assume the server returns a correct response!
        Ok((packet, _)) => packet,
        Err(packet) => packet,
    };
    println!("{:?}", res);
    res
}
