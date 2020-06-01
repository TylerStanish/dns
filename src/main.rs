use std::collections::HashMap;
use std::net::{UdpSocket};
use byteorder::{ByteOrder, BigEndian};

#[derive(Debug, PartialEq)]
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
    pub fn new() -> Self {
        DnsHeader {
            tx_id: 0,
            is_response: false,
            opcode: 0,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            response_code: 0,
            questions_count: 0,
            answers_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let tx_id = BigEndian::read_u16(bytes);
        let flags = &bytes[2..4];
        let questions_count = BigEndian::read_u16(&bytes[4..6]);
        let answers_count = BigEndian::read_u16(&bytes[6..8]);
        let authority_count = BigEndian::read_u16(&bytes[8..10]);
        let additional_count = BigEndian::read_u16(&bytes[10..12]);
        DnsHeader {
            tx_id,
            is_response: flags[0] & 0x80 > 0,
            opcode: Self::opcode(&flags[0]),
            authoritative: (flags[0] & 0x04) > 0,
            truncated: flags[0] & 0x02 > 0,
            recursion_desired: flags[0] & 0x01 > 0,
            recursion_available: flags[1] & 0x80 > 0,
            z: flags[1] & 0x70,
            response_code: flags[1] & 0x0f,
            questions_count,
            answers_count,
            authority_count,
            additional_count,
        }
    }

    /// In the flags section, the opcode is
    /// .xxx x... .... ....
    fn opcode(byte: &u8) -> u8 {
        let mut res = byte & 0x70;
        res << 1;
        res += byte & 0x08;
        res
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
            0xffu8, 0xffu8, // transaction id
            0x00u8, 0x00u8, // flags (standard query request)
            0x00u8, 0x01u8, // 1 question
            0x00u8, 0x00u8, // dns request, so no answer rr's here of course
            0x00u8, 0x00u8, // neither authority rr's
            0x00u8, 0x00u8, // nor additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(&bytes);
        let mut expected_header = DnsHeader::new();
        expected_header.tx_id = 0xffff;
        expected_header.questions_count = 1;

        assert_eq!(expected_header, actual_header);
    }

    #[test]
    fn test_header_from_bytes_with_more_nonzero_flags() {
        let bytes = [
            0xffu8, 0xffu8, // transaction id
            0x81u8, 0x85u8, // flags (standard query request)
            0x00u8, 0x01u8, // 1 question
            0x00u8, 0x00u8, // dns request, so no answer rr's here of course
            0x00u8, 0x00u8, // neither authority rr's
            0x00u8, 0x00u8, // nor additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(&bytes);
        let mut expected_header = DnsHeader::new();
        expected_header.tx_id = 0xffff;
        expected_header.is_response = true;
        expected_header.recursion_desired = true;
        expected_header.recursion_available = true;
        expected_header.questions_count = 1;
        expected_header.response_code = 5;

        assert_eq!(expected_header, actual_header);
    }

    #[test]
    fn test_request_from_bytes() {
        let bytes = [
            0xffu8, 0xffu8, // transaction id
            0x01u8, 0x00u8, // flags (standard query request)
            0x00u8, 0x01u8, // 1 question
            0x00u8, 0x00u8, // dns request, so no answer rr's here of course
            0x00u8, 0x00u8, // neither authority rr's
            0x00u8, 0x00u8, // nor additional rr's
        ];
        unimplemented!()
    }
}
