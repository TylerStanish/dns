use std::collections::HashMap;
use std::net::UdpSocket;
use byteorder::{ByteOrder, BigEndian, WriteBytesExt};
use resize_slice::ResizeSlice;

mod serialization;

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

    pub fn to_bytes(self) -> [u8; 12] {
        let mut res: [u8; 12] = [0; 12];
        BigEndian::write_u16(&mut res, self.tx_id);
        let mut flags = 0u16;
        flags = self.is_response as u16;
        flags <<= 4;
        flags += self.opcode as u16;
        flags <<= 1;
        flags += self.authoritative as u16;
        flags <<= 1;
        flags += self.truncated as u16;
        flags <<= 1;
        flags += self.recursion_desired as u16;
        flags <<= 1;
        flags += self.recursion_available as u16;
        flags <<= 3;
        flags += self.z as u16;
        flags <<= 4;
        flags += self.response_code as u16;
        res[2] = ((flags & 0xff00) >> 8) as u8;
        res[3] = (flags & 0x00ff) as u8;
        BigEndian::write_u16(&mut res[4..], self.questions_count);
        BigEndian::write_u16(&mut res[6..], self.answers_count);
        BigEndian::write_u16(&mut res[8..], self.authority_count);
        BigEndian::write_u16(&mut res[10..], self.additional_count);
        res
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
        //let ending = bytes.iter().position(|n| *n == 0).unwrap(); // TODO don't unwrap this, handle the bad input user gave us
        //println!("{:?}", std::str::from_utf8(&bytes[..ending]));


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

    pub fn to_bytes(self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.append(&mut serialization::serialize_domain_to_bytes(&self.name));
        res.push(((self.qtype & 0xff00) >> 8) as u8);
        res.push((self.qtype & 0x00ff) as u8);
        res.push(((self.class & 0xff00) >> 8) as u8);
        res.push((self.class & 0x00ff) as u8);
        res
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

    pub fn to_bytes(self) -> Vec<u8> {
        let mut res = Vec::new();
        res.append(&mut serialization::serialize_domain_to_bytes(&self.name));
        res.write_u16::<BigEndian>(self.qtype).unwrap(); // TODO don't unwrap, handle error, return error response
        res.write_u16::<BigEndian>(self.class).unwrap();
        res.write_u32::<BigEndian>(self.ttl).unwrap();
        res.write_u16::<BigEndian>(self.data_length).unwrap();
        res.write_u32::<BigEndian>(self.address).unwrap();
        res
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
        bytes.resize_from(12);
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
    use pretty_assertions::assert_eq;

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
            0x62, 0x61, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.bar.com
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
            0x00, 0x00, // flags (standard query request)
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
            0x00, 0x00, // flags (standard query request)
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
        expected_packet.header.questions_count = 1;
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
            0x00u8, 0x00, // transaction id
            0x00, 0x00, // flags (standard query request)
            0x00, 0x02, // 2 questions
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
        expected_packet.header.questions_count = 2;
        let mut foo_query = DnsQuery::new();
        foo_query.name = "foo.com".to_owned();
        foo_query.qtype = 1;
        foo_query.class = 1;
        let mut purdue_query = DnsQuery::new();
        purdue_query.name = "foo.com".to_owned();
        purdue_query.qtype = 1;
        purdue_query.class = 1;
        expected_packet.queries = vec![foo_query, purdue_query];
        expected_packet.answers = Vec::new();

        assert_eq!(expected_packet, actual_packet);
    }

    #[test]
    fn test_header_to_bytes_all_zero() {
        let header = DnsHeader::new();
        let actual_bytes = header.to_bytes();
        let expected_bytes = [0u8; 12];
        assert_eq!(expected_bytes, actual_bytes);
    }

    #[test]
    fn test_response_header_to_bytes() {
        let mut header = DnsHeader::new();
        header.tx_id = 0xbeef;
        header.is_response = true;
        header.authoritative = true;
        header.truncated = true;
        header.recursion_desired = true;
        header.recursion_available = true;
        header.response_code = 5;
        header.questions_count = 0xabcd;
        header.answers_count = 0xabcd;
        header.authority_count = 0xabcd;
        header.additional_count = 0xabcd;
        let actual_bytes = header.to_bytes();
        let expected_bytes = [
            0xbeu8, 0xef,
            0x87, 0x85,
            0xab, 0xcd,
            0xab, 0xcd,
            0xab, 0xcd,
            0xab, 0xcd,
        ];
        assert_eq!(expected_bytes, actual_bytes);
    }

    #[test]
    fn test_dns_query_to_bytes_all_zero() {
        let query = DnsQuery::new();
        let actual_bytes = query.to_bytes();
        let expected_bytes = [0x00u8, 0x00, 0x00, 0x00].to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }

    #[test]
    fn test_dns_query_to_bytes() {
        let mut query = DnsQuery::new();
        query.name = "foo.bar.com".to_owned();
        query.qtype = 0xabcd;
        query.class = 0x0123;
        let actual_bytes = query.to_bytes();
        let expected_bytes = [
            0x03u8, 0x66u8, 0x6f, 0x6f, 0x00,
            0x03, 0x62, 0x61, 0x72, 0x00,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
        ].to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }

    #[test]
    fn test_dns_answer_to_bytes_all_zero() {
        let ans = DnsAnswer::new();
        let actual_bytes = ans.to_bytes();
        let expected_bytes = [0; 14].to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }

    #[test]
    fn test_dns_answer_to_bytes() {
        let mut ans = DnsAnswer::new();
        ans.name = "foo.bar.com".to_owned();
        ans.qtype = 0xabcd;
        ans.class = 0x0123;
        ans.ttl = 0x456789ab;
        ans.data_length = 0xbeef;
        ans.address = 0xdecafbad;
        let actual_bytes = ans.to_bytes();
        let expected_bytes = [
            0x03u8, 0x66u8, 0x6f, 0x6f, 0x00,
            0x03, 0x62, 0x61, 0x72, 0x00,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
            0x45, 0x67, 0x89, 0xab,
            0xbe, 0xef,
            0xde, 0xca, 0xfb, 0xad,
        ].to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }
}
