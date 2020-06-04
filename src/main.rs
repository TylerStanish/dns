use std::collections::HashMap;
use std::net::UdpSocket;
use byteorder::{ByteOrder, BigEndian};
use resize_slice::ResizeSlice;

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
        let mut res = byte & 0x78;
        res >>= 3;
        res
    }
}

#[derive(Debug, PartialEq)]
struct DnsQuery {
    name: String,
    qtype: u16,
    class: u16,
}

impl DnsQuery {
    pub fn new() -> Self {
        DnsQuery {
            name: String::new(),
            qtype: 0,
            class: 0,
        }
    }

    /// This function modifies the `bytes` parameter so the caller of this
    /// function can continue off at the slice's zero index
    ///
    /// Remember according to the rfc:
    /// 'each label consists of a length octet followed by that
    /// number of octets.  The domain name terminates with the
    /// zero length octet for the null label of the root.  Note
    /// that this field may be an odd number of octets; no
    /// padding is used.'
    pub fn from_bytes(mut bytes: &mut [u8]) -> Self {
        let name_len = bytes[0];
        let mut name = String::with_capacity(name_len as usize);
        let mut curr_byte = 0;
        loop {
            let len = bytes[curr_byte];
            curr_byte += 1; // consume the size byte
            for i in curr_byte..(curr_byte as u8 + len) as usize {
                name.push(bytes[i] as char);
            }
            curr_byte += len as usize;
            if bytes[curr_byte] == 0 {
                break
            }
            name.push('.');
        }
        curr_byte += 1; // consume zero octet
        let qtype = BigEndian::read_u16(&bytes[curr_byte..curr_byte+2]);
        let class = BigEndian::read_u16(&bytes[curr_byte+2..curr_byte+4]);
        // resize the slice so the caller of this function can continue
        // and not have to do any arithmetic or handle a tuple return type
        // or extra pointer variable
        bytes.resize_from(curr_byte+4);
        DnsQuery {
            name,
            qtype,
            class,
        }
    }
}

#[derive(Debug, PartialEq)]
struct DnsAnswer {
    name: String,
    qtype: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    address: u32, // ipv4
}

impl DnsAnswer {
    pub fn new() -> Self {
        DnsAnswer {
            name: String::new(),
            qtype: 0,
            class: 0,
            ttl: 0,
            data_length: 0,
            address: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
struct DnsPacket {
    header: DnsHeader,
    queries: Vec<DnsQuery>,
    answers: Vec<DnsAnswer>,
}

impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            queries: Vec::new(),
            answers: Vec::new(),
        }
    }

    pub fn from_bytes(mut bytes: &mut [u8]) -> Self {
        let header = DnsHeader::from_bytes(&bytes[..12]);
        // TODO check if the header says this is a request or response
        // If from response, then why are we even calling this function?
        let mut queries = Vec::with_capacity(header.questions_count as usize);
        bytes.resize_from(13);
        for _ in 0..header.questions_count {
            queries.push(DnsQuery::from_bytes(bytes));
        }
        DnsPacket {
            header,
            queries,
            answers: Vec::new(),
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
        let mut bytes = [
            0xffu8, 0xff, // transaction id
            0x00, 0x00, // flags (standard query request)
            0x00, 0x01, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(&mut bytes);
        let mut expected_header = DnsHeader::new();
        expected_header.tx_id = 0xffff;
        expected_header.questions_count = 1;

        assert_eq!(expected_header, actual_header);
    }

    #[test]
    fn test_header_from_bytes_with_more_nonzero_flags() {
        let mut bytes = [
            0xff, 0xff, // transaction id
            0x81, 0x85, // flags (standard query request)
            0x00, 0x01, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(&mut bytes);
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
    fn test_header_from_bytes_with_more_nonzero_flags_and_opcode() {
        let mut bytes = [
            0xffu8, 0xff, // transaction id
            0xf9, 0x85, // flags (standard query request)
            0x00, 0x01, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(&mut bytes);
        let mut expected_header = DnsHeader::new();
        expected_header.tx_id = 0xffff;
        expected_header.opcode = 0x0f;
        expected_header.is_response = true;
        expected_header.recursion_desired = true;
        expected_header.recursion_available = true;
        expected_header.questions_count = 1;
        expected_header.response_code = 5;

        assert_eq!(expected_header, actual_header);
    }

    #[test]
    /// mostly testing for endianness
    fn test_header_from_bytes_with_nonzero_counts() {
        let mut bytes = [
            0x00u8, 0x00, // transaction id
            0x00, 0x00, // flags (standard query request)
            0x00, 0x00, // 0 questions
            0x00, 0x01, // 1 answer rr
            0x01, 0x00, // 256 authority rr's
            0x00, 0x00, // additional rr's
        ];
        let actual_header = DnsHeader::from_bytes(&mut bytes);
        let mut expected_header = DnsHeader::new();
        expected_header.answers_count = 1;
        expected_header.authority_count = 256;

        assert_eq!(expected_header, actual_header);
    }

    #[test]
    /// mostly testing for endianness
    fn test_query_from_bytes() {
        let mut bytes = [
            0x03, // length of 'foo'
            0x66u8, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let actual_query = DnsQuery::from_bytes(&mut bytes);
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.com".to_owned();
        expected_query.qtype = 1;
        expected_query.class = 1;

        assert_eq!(expected_query, actual_query);
    }

    #[test]
    fn test_query_from_bytes_multiple_queries() {
        let mut bytes = [
            0x03, // length of 'foo'
            0x66u8, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let actual_query = DnsQuery::from_bytes(&mut bytes);
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.com".to_owned();
        expected_query.qtype = 1;
        expected_query.class = 1;

        assert_eq!(expected_query, actual_query);
    }

    #[test]
    fn test_query_from_bytes_with_subdomain() {
        let mut bytes = [
            0x03u8, // length of 'foo'
            0x66, 0x6f, 0x6f, 
            0x03, // length of 'bar'
            0x62, 0x61, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.bar.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let actual_query = DnsQuery::from_bytes(&mut bytes);
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.bar.com".to_owned();
        expected_query.qtype = 1;
        expected_query.class = 1;

        assert_eq!(expected_query, actual_query);
    }

    #[test]
    fn test_request_from_bytes_zero_questions() {
        let mut bytes = [
            0x00u8, 0x00, // transaction id
            0x01, 0x00, // flags (standard query request)
            0x00, 0x00, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
        ];
        let actual_packet = DnsPacket::from_bytes(&mut bytes);
        let mut expected_packet = DnsPacket::new();
        expected_packet.header = DnsHeader::new();

        assert_eq!(expected_packet, actual_packet);
    }

    #[test]
    fn test_request_from_bytes_with_one_question() {
        let mut bytes = [
            0x00u8, 0x00, // transaction id
            0x01, 0x00, // flags (standard query request)
            0x00, 0x01, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
            0x03, // length of 'foo'
            0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let actual_packet = DnsPacket::from_bytes(&mut bytes);
        let mut expected_packet = DnsPacket::new();
        let mut query = DnsQuery::new();
        query.name = "foo.com".to_owned();
        query.qtype = 1;
        query.class = 1;
        expected_packet.queries = vec![query];
        expected_packet.answers = Vec::new();

        assert_eq!(expected_packet, actual_packet);
    }

    #[test]
    fn test_request_from_bytes_with_many_questions() {
        let mut bytes = [
            0xffu8, 0xff, // transaction id
            0x01, 0x00, // flags (standard query request)
            0x00, 0x01, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
            // queries
            0x03, // length of 'foo'
            0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
            0x06, // length of 'purdue'
            0x70, 0x75, 0x72, 0x64, 0x75, 0x65, 0x03, 0x65, 0x66, 0x75, // purdue.edu
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let actual_packet = DnsPacket::from_bytes(&mut bytes);
        let mut expected_packet = DnsPacket::new();
        let mut foo_query = DnsQuery::new();
        foo_query.name = "foo.com".to_owned();
        foo_query.qtype = 2;
        foo_query.class = 1;
        let mut purdue_query = DnsQuery::new();
        purdue_query.name = "foo.com".to_owned();
        purdue_query.qtype = 2;
        purdue_query.class = 1;
        expected_packet.queries = vec![purdue_query];
        expected_packet.answers = Vec::new();

        assert_eq!(expected_packet, actual_packet);
    }
}
