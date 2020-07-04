use serialization::{FromBytes, ToBytes};
use std::net::UdpSocket;
use ttl_cache::TtlCache;

mod answer;
mod authority;
mod cache;
mod client;
mod header;
mod packet;
mod query;
mod record;
mod resolvers;
mod serialization;

fn main() {
    // calling this when the server is starting so that you know if the user
    // entered any invalid yaml configuration files, therefore it will fail early
    // before serving any requests
    authority::authorities();

    let sock = UdpSocket::bind("0.0.0.0:5553").expect("Could not create server");
    let mut cache = TtlCache::<query::DnsQuery, answer::DnsAnswer>::new(1024);
    let client = client::DnsClient::new(&resolvers::default_resolver, &mut cache);
    loop {
        let mut buf = [0; 1024];
        let (nread, src) = sock.recv_from(&mut buf).unwrap();
        let result = match packet::DnsPacket::from_bytes(&mut buf[..nread]) {
            Ok((packet, _)) => client.results(packet),
            Err(_) => {
                let mut packet = packet::DnsPacket::new();
                packet.header.response_code = header::ResponseCode::FormatError;
                packet
            }
        };
        sock.send_to(&result.to_bytes(), &src).unwrap();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_invalid_yaml_fails_early() {
        unimplemented!()
    }
}
