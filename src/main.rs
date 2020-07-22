use serialization::{FromBytes, ToBytes};
use std::net::UdpSocket;
use ttl_cache::TtlCache;

mod answer;
mod authority;
mod blocklist;
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

    let sock = UdpSocket::bind("0.0.0.0:5554").expect("Could not create server");
    let mut cache = TtlCache::<query::DnsQuery, answer::DnsAnswer>::new(1024);
    let client = client::DnsClient::new(&resolvers::default_resolver, &mut cache);
    loop {
        let mut buf = [0; 1024];
        let (nread, src) = sock.recv_from(&mut buf).unwrap();
        match packet::DnsPacket::from_bytes(&mut buf[..nread]) {
            Ok((packet, _)) => {
                match client.results(packet) {
                    Ok(packet) => {
                        sock.send_to(&packet.to_bytes(), &src).unwrap();
                    },
                    Err(()) => (), // simply don't return any packets as the domain hit the blocklist
                };
            },
            Err(_) => {
                let mut packet = packet::DnsPacket::new();
                packet.header.response_code = header::ResponseCode::FormatError;
                sock.send_to(&packet.to_bytes(), &src).unwrap();
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use tempdir::TempDir;

    #[test]
    #[should_panic]
    fn test_invalid_yaml_fails_early() {
        let temp_authorities_dir = TempDir::new("authorities").unwrap();
        let authority_file_path = temp_authorities_dir.path().join("authority1.yml");
        env::set_var("AUTHORITY_DIR", temp_authorities_dir.path());
        let mut authority_file = File::create(authority_file_path).unwrap();
        let input = b"
origin: foo.com
records:
  - type: SOA
    class: IN
    ttl: 60
    name: bar
    data:
      domain: foo
      fqdn: soa.foo.com.
      email: foo@foo.com
      serial: 42
      refresh: 43
      retry: 44
      expire: 45
      minimum: 46
";
        authority_file.write_all(input).unwrap();
        main();
    }
}
