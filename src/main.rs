use std::collections::HashMap;
use std::net::{UdpSocket};
use byteorder::{ByteOrder, BigEndian};

struct DnsHeader {
    tx_id: u16,
    is_response: bool,
    opcode: u8, // only 4 bits actually
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    z: u8,
    response_code: u8,
    questions_count: u16,
    answers_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl DnsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let tx_id = BigEndian::read_u16(bytes);
        let flags = &bytes[2..4];
        let questions = BigEndian::read_u16(&bytes[4..6]);
        let answers_count = BigEndian::read_u16(&bytes[6..8]);
        let authority_count = BigEndian::read_u16(&bytes[8..10]);
        let additional_count = BigEndian::read_u16(&bytes[10..12]);
        DnsHeader {
            tx_id,
            is_response: flags[0] & 0x8 as bool,
            opcode: (flags[0] & 0x7)
        }
    }
}

fn main() {
    let sock = UdpSocket::bind("0.0.0.0:4567").expect("Could not create server");
    loop {
        let mut buf = [0; 1024];
        let nread = sock.recv(&mut buf).unwrap();
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_from_bytes() {
        let bytes = [
            0xffi8, 0xffi8, // transaction id
            0x01i8, 0x00i8, // flags (standard query request)
            0x00i8, 0x01i8, // 1 question
            0x00i8, 0x00i8, // dns request, so no answer rr's here of course
            0x00i8, 0x00i8, // neither authority rr's
            0x00i8, 0x00i8, // nor additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(bytes);
        let expected_header = DnsHeader::new();
    }

    #[test]
    fn test_request_from_bytes() {
        let bytes = [
            0xffi8, 0xffi8, // transaction id
            0x01i8, 0x00i8, // flags (standard query request)
            0x00i8, 0x01i8, // 1 question
            0x00i8, 0x00i8, // dns request, so no answer rr's here of course
            0x00i8, 0x00i8, // neither authority rr's
            0x00i8, 0x00i8, // nor additional rr's
        ];
    }
}
