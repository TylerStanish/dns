use resize_slice::ResizeSlice;
use crate::answer::DnsAnswer;
use crate::client;
use crate::query::DnsQuery;
use crate::header::DnsHeader;
use crate::serialization::{FromBytes, ToBytes};

#[derive(Debug, PartialEq, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            queries: Vec::new(),
            answers: Vec::new(),
        }
    }

    pub fn new_error(err: u8) -> Self {
        let mut packet = DnsPacket::new_response();
        packet.header.response_code = err;
        packet
    }

    pub fn new_response() -> Self {
        let mut packet = DnsPacket::new();
        packet.header.is_response = true;
        packet
    }
}

impl FromBytes for DnsPacket {
    fn from_bytes(mut bytes: &[u8]) -> (Self, usize) {
        let (header, mut total_num_read) = DnsHeader::from_bytes(&bytes[..12]);
        // TODO check if the header says this is a request or response
        // If from response, then why are we even calling this function?
        let mut queries = Vec::with_capacity(header.questions_count as usize);
        bytes.resize_from(12);
        for _ in 0..header.questions_count {
            let (query, num_read) = DnsQuery::from_bytes(&bytes);
            queries.push(query);
            bytes.resize_from(num_read);
            total_num_read += num_read;
        }
        (DnsPacket {
            header,
            queries,
            answers: Vec::new(),
        }, total_num_read)
    }
}

impl ToBytes for DnsPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.append(&mut self.header.to_bytes().to_vec());
        res.append(&mut self.queries.iter().flat_map(|query| query.to_bytes()).collect::<Vec<u8>>());
        res.append(&mut self.answers.iter().flat_map(|answer| answer.to_bytes()).collect::<Vec<u8>>());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

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
        let (actual_packet, _) = DnsPacket::from_bytes(&mut bytes);
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
        let (actual_packet, _) = DnsPacket::from_bytes(&mut bytes);
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
        let (actual_packet, _) = DnsPacket::from_bytes(&mut bytes);
        let mut expected_packet = DnsPacket::new();
        expected_packet.header.questions_count = 2;
        let mut foo_query = DnsQuery::new();
        foo_query.name = "foo.com".to_owned();
        foo_query.qtype = 1;
        foo_query.class = 1;
        let mut purdue_query = DnsQuery::new();
        purdue_query.name = "purdue.edu".to_owned();
        purdue_query.qtype = 1;
        purdue_query.class = 1;
        expected_packet.queries = vec![foo_query, purdue_query];
        expected_packet.answers = Vec::new();

        assert_eq!(expected_packet, actual_packet);
    }

    #[test]
    fn test_packet_to_bytes_and_from_bytes() {
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
            0x70, 0x75, 0x72, 0x64, 0x75, 0x65, 0x03, 0x65, 0x66, 0x75, 0x00, // purdue.edu
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ].to_vec();
        let (packet, _) = DnsPacket::from_bytes(&mut bytes);
        assert_eq!(packet.to_bytes().to_vec(), bytes);
    }
}