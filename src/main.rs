use std::net::UdpSocket;

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
    }
}