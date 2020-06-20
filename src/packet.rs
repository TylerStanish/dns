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
    /// The answer, authority, and additional sections all share the same
    /// format: a variable number of resource records, where the number of
    /// records is specified in the corresponding count field in the header.
    pub authority: Vec<DnsAnswer>,
    pub additional: Vec<DnsAnswer>,
}

impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            queries: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
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
        let mut answers = Vec::with_capacity(header.answers_count as usize);
        let mut authority = Vec::with_capacity(header.authority_count as usize);
        let mut additional = Vec::with_capacity(header.additional_count as usize);
        bytes.resize_from(total_num_read);
        for _ in 0..header.questions_count {
            let (query, num_read) = DnsQuery::from_bytes(&bytes);
            queries.push(query);
            total_num_read += num_read;
            bytes.resize_from(num_read);
        }
        for _ in 0..header.answers_count {
            let (answer, num_read) = DnsAnswer::from_bytes(&bytes);
            answers.push(answer);
            total_num_read += num_read;
            bytes.resize_from(num_read);
        }
        for _ in 0..header.authority_count {
            let (answer, num_read) = DnsAnswer::from_bytes(&bytes);
            authority.push(answer);
            total_num_read += num_read;
            bytes.resize_from(num_read);
        }
        for _ in 0..header.additional_count {
            let (answer, num_read) = DnsAnswer::from_bytes(&bytes);
            additional.push(answer);
            total_num_read += num_read;
            bytes.resize_from(num_read);
        }
        (DnsPacket {
            header,
            queries,
            answers,
            authority,
            additional,
        }, total_num_read)
    }
}

impl ToBytes for DnsPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.append(&mut self.header.to_bytes().to_vec());
        res.append(&mut self.queries.iter().flat_map(|query| query.to_bytes()).collect::<Vec<u8>>());
        res.append(&mut self.answers.iter().flat_map(|answer| answer.to_bytes()).collect::<Vec<u8>>());
        res.append(&mut self.authority.iter().flat_map(|authority| authority.to_bytes()).collect::<Vec<u8>>());
        res.append(&mut self.additional.iter().flat_map(|additional| additional.to_bytes()).collect::<Vec<u8>>());
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
            0x70, 0x75, 0x72, 0x64, 0x75, 0x65, 0x03, 0x65, 0x64, 0x75, 0x00, // purdue.edu
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

    #[test]
    fn test_packet_from_bytes_with_one_answer() {
        let bytes = [
            0x00u8, 0x00, // transaction id
            0x80, 0x00, // flags (standard query response)
            0x00, 0x00, // 0 questions
            0x00, 0x01, // 1 answer
            0x00, 0x00,
            0x00, 0x00,
            // answer
            0x03u8, 0x66, 0x6f, 0x6f,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
            0x45, 0x67, 0x89, 0xab,
            0xbe, 0xef,
            0xde, 0xca, 0xfb, 0xad,
        ];
        let (packet, num_read) = DnsPacket::from_bytes(&bytes);
        assert_eq!(bytes.len(), num_read);
        let mut answer = DnsAnswer::new();
        answer.name = "foo.com".to_owned();
        answer.qtype = 0xabcd;
        answer.class = 0x0123;
        answer.ttl = 0x456789ab;
        answer.data_length = 0xbeef;
        answer.address = 0xdecafbad;
        assert_eq!(vec![answer], packet.answers);
    }

    #[test]
    fn test_packet_from_bytes_with_many_answers() {
        let bytes = [
            0x00u8, 0x00, // transaction id
            0x80, 0x00, // flags (standard query response)
            0x00, 0x00, // 0 questions
            0x00, 0x02, // 2 answers
            0x00, 0x00,
            0x00, 0x00,
            // answers
            //foo.com
            0x03u8, 0x66, 0x6f, 0x6f,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
            0x45, 0x67, 0x89, 0xab,
            0xbe, 0xef,
            0xde, 0xca, 0xfb, 0xad,
            // bar.com
            0x03, 0x62, 0x61, 0x72,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
            0x45, 0x67, 0x89, 0xab,
            0xbe, 0xef,
            0xde, 0xca, 0xfb, 0xad,
        ];
        let (packet, num_read) = DnsPacket::from_bytes(&bytes);
        assert_eq!(bytes.len(), num_read);
        let mut foo_answer = DnsAnswer::new();
        foo_answer.name = "foo.com".to_owned();
        foo_answer.qtype = 0xabcd;
        foo_answer.class = 0x0123;
        foo_answer.ttl = 0x456789ab;
        foo_answer.data_length = 0xbeef;
        foo_answer.address = 0xdecafbad;
        let mut bar_answer = DnsAnswer::new();
        bar_answer.name = "bar.com".to_owned();
        bar_answer.qtype = 0xabcd;
        bar_answer.class = 0x0123;
        bar_answer.ttl = 0x456789ab;
        bar_answer.data_length = 0xbeef;
        bar_answer.address = 0xdecafbad;
        assert_eq!(vec![foo_answer, bar_answer], packet.answers);
    }

    #[test]
    fn test_packet_additional_and_authority() {
        let bytes = [
            0x00u8, 0x00, // transaction id
            0x80, 0x00, // flags (standard query response)
            0x00, 0x00, // 0 questions
            0x00, 0x00, // 2 answers
            0x00, 0x01,
            0x00, 0x01,
            // answers
            //foo.com
            0x03u8, 0x66, 0x6f, 0x6f,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
            0x45, 0x67, 0x89, 0xab,
            0xbe, 0xef,
            0xde, 0xca, 0xfb, 0xad,
            // bar.com
            0x03, 0x62, 0x61, 0x72,
            0x03, 0x63, 0x6f, 0x6d, 0x00,
            0xab, 0xcd,
            0x01, 0x23,
            0x45, 0x67, 0x89, 0xab,
            0xbe, 0xef,
            0xde, 0xca, 0xfb, 0xad,
        ];
        let (packet, num_read) = DnsPacket::from_bytes(&bytes);
        assert_eq!(bytes.len(), num_read);
        assert_eq!(packet.to_bytes().to_vec(), bytes.to_vec());
    }
    // TODO test multiple answers of additional and authority rrs
}