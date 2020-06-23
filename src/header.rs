use std::convert::TryInto;
use byteorder::{ByteOrder, NetworkEndian};
use crate::serialization::{FromBytes, ToBytes};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum ResourceType {
    A,
    AAAA,
}

impl ResourceType {
    pub fn as_u16(&self) -> u16 {
        match self {
            Self::A => 1,
            Self::AAAA => 28,
            _ => 0, // FIXME should this be 0?
        }
    }
}

impl TryInto<ResourceType> for u16 {
    type Error = ();
    fn try_into(self) -> Result<ResourceType, Self::Error> {
        match self {
            1 => Ok(ResourceType::A),
            28 => Ok(ResourceType::AAAA),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerError,
    NameError,
    NotImplemented,
    Refused,
}

impl ResponseCode {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormatError => 1,
            Self::ServerError => 2,
            Self::NameError => 3,
            Self::NotImplemented => 4,
            Self::Refused => 5,
        }
    }
}

impl ToBytes for ResponseCode {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::NoError => vec![0],
            Self::FormatError => vec![1],
            Self::ServerError => vec![2],
            Self::NameError => vec![3],
            Self::NotImplemented => vec![4],
            Self::Refused => vec![5],
        }
    }
}

impl TryInto<ResponseCode> for u8 {
    type Error = ();
    fn try_into(self) -> Result<ResponseCode, Self::Error> {
        match self {
            0 => Ok(ResponseCode::NoError),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServerError),
            3 => Ok(ResponseCode::NameError),
            4 => Ok(ResponseCode::NotImplemented),
            5 => Ok(ResponseCode::Refused),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DnsHeader {
    pub tx_id: u16,
    pub is_response: bool,
    pub opcode: u8, // only 4 bits actually
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: u8,
    pub response_code: ResponseCode,
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
            response_code: ResponseCode::NoError,
            questions_count: 0,
            answers_count: 0,
            authority_count: 0,
            additional_count: 0,
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

impl FromBytes for DnsHeader {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), ()> {
        let tx_id = NetworkEndian::read_u16(bytes);
        let flags = &bytes[2..4];
        let questions_count = NetworkEndian::read_u16(&bytes[4..6]);
        let answers_count = NetworkEndian::read_u16(&bytes[6..8]);
        let authority_count = NetworkEndian::read_u16(&bytes[8..10]);
        let additional_count = NetworkEndian::read_u16(&bytes[10..12]);
        Ok((DnsHeader {
            tx_id,
            is_response: flags[0] & 0x80 > 0,
            opcode: Self::opcode(&flags[0]),
            authoritative: flags[0] & 0x04 > 0,
            truncated: flags[0] & 0x02 > 0,
            recursion_desired: flags[0] & 0x01 > 0,
            recursion_available: flags[1] & 0x80 > 0,
            z: (flags[1] & 0x70) >> 4,
            response_code: (flags[1] & 0x0f).try_into().unwrap(),
            questions_count,
            answers_count,
            authority_count,
            additional_count,
        }, 12))
    }
}

impl ToBytes for DnsHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res: [u8; 12] = [0; 12];
        NetworkEndian::write_u16(&mut res, self.tx_id);
        let mut flags = 0u16;
        flags = self.is_response as u16;
        flags <<= 4;
        flags += (self.opcode & 0x0f) as u16;
        flags <<= 1;
        flags += self.authoritative as u16;
        flags <<= 1;
        flags += self.truncated as u16;
        flags <<= 1;
        flags += self.recursion_desired as u16;
        flags <<= 1;
        flags += self.recursion_available as u16;
        flags <<= 3;
        // TODO `&` each value you add with its max value!!!
        flags += (self.z & 0x07) as u16;
        flags <<= 4;
        flags += (self.response_code & 0x0f) as u16;
        res[2] = ((flags & 0xff00) >> 8) as u8;
        res[3] = (flags & 0x00ff) as u8;
        NetworkEndian::write_u16(&mut res[4..], self.questions_count);
        NetworkEndian::write_u16(&mut res[6..], self.answers_count);
        NetworkEndian::write_u16(&mut res[8..], self.authority_count);
        NetworkEndian::write_u16(&mut res[10..], self.additional_count);
        res.to_vec()
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
        let (actual_header, _) = DnsHeader::from_bytes(&mut bytes).unwrap();
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
        let (actual_header, _) = DnsHeader::from_bytes(&mut bytes).unwrap();
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
        let (actual_header, _) = DnsHeader::from_bytes(&mut bytes).unwrap();
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
        let (actual_header, _) = DnsHeader::from_bytes(&mut bytes).unwrap();
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
        assert_eq!(expected_bytes.to_vec(), actual_bytes);
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
        assert_eq!(expected_bytes.to_vec(), actual_bytes);
    }

    /// FIXME This is a really important test for security, also all possible
    /// numbers that can be smaller than their rust type counterpart (e.g. z
    /// holds 3 bits in practice but we put it in a u8
    #[test]
    fn test_z_in_bounds() {
        let mut header = DnsHeader::new();
        header.tx_id = 0xbeef;
        header.z = 7;
        let actual_bytes = header.to_bytes();
        let expected_bytes = [
            0xbeu8, 0xef,
            0x00, 0x70,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(expected_bytes.to_vec(), actual_bytes);
    }

    /// FIXME This is a really important test for security
    #[test]
    fn test_z_out_of_bounds() {
        let mut header = DnsHeader::new();
        header.tx_id = 0xbeef;
        header.z = 32;
        let actual_bytes = header.to_bytes();
        let expected_bytes = [
            0xbeu8, 0xef,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(expected_bytes.to_vec(), actual_bytes);
    }

    /// FIXME This is a really important test for security
    #[test]
    fn test_multibit_from_bytes_and_bounds() {
        let mut bytes = [
            0xffu8, 0xff, // transaction id
            0x48, 0x79, // flags (standard query request)
            0x00, 0x00, // 1 question
            0x00, 0x00, // dns request, so no answer rr's here of course
            0x00, 0x00, // neither authority rr's
            0x00, 0x00, // nor additional rr's
        ];
        let (actual_header, _) = DnsHeader::from_bytes(&mut bytes).unwrap();
        let mut expected_header = DnsHeader::new();
        expected_header.tx_id = 0xffff;
        expected_header.opcode = 9;
        expected_header.z = 7;
        expected_header.response_code = 9.try_into().unwrap();

        assert_eq!(expected_header, actual_header);
    }
}