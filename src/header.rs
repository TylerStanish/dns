use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};

#[derive(Debug, PartialEq)]
pub struct DnsHeader {
    pub tx_id: u16,
    pub is_response: bool,
    pub opcode: u8, // only 4 bits actually
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: u8,
    pub response_code: u8,
    pub questions_count: u16,
    pub answers_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
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
        let tx_id = NetworkEndian::read_u16(bytes);
        let flags = &bytes[2..4];
        let questions_count = NetworkEndian::read_u16(&bytes[4..6]);
        let answers_count = NetworkEndian::read_u16(&bytes[6..8]);
        let authority_count = NetworkEndian::read_u16(&bytes[8..10]);
        let additional_count = NetworkEndian::read_u16(&bytes[10..12]);
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
        NetworkEndian::write_u16(&mut res, self.tx_id);
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
        NetworkEndian::write_u16(&mut res[4..], self.questions_count);
        NetworkEndian::write_u16(&mut res[6..], self.answers_count);
        NetworkEndian::write_u16(&mut res[8..], self.authority_count);
        NetworkEndian::write_u16(&mut res[10..], self.additional_count);
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

}