use crate::header::{ResourceType, ResponseCode};
use crate::serialization::{
    deserialize_domain_from_bytes, serialize_domain_to_bytes, FromBytes, ToBytes,
};
use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use std::convert::TryInto;

#[derive(Debug, PartialEq, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub qtype: ResourceType,
    pub class: u16,
    pub ttl: u32,
    pub data_length: u16,
    pub rdata: Vec<u8>,
}

impl DnsAnswer {
    pub fn new() -> Self {
        DnsAnswer {
            name: String::new(),
            qtype: ResourceType::Unused,
            class: 1,
            ttl: 0,
            data_length: 0,
            rdata: vec![],
        }
    }

    pub fn from_bytes(packet_bytes: &[u8], bytes: &[u8]) -> Result<(Self, usize), Self> {
        let (name, mut bytes_read) = match deserialize_domain_from_bytes(&packet_bytes, &bytes) {
            Ok(tup) => tup,
            Err(_) => return Err(DnsAnswer::new()),
        };
        let qtype: ResourceType = match NetworkEndian::read_u16(&bytes[bytes_read..]).try_into() {
            Ok(rrtype) => rrtype,
            _ => return Err(DnsAnswer::new()),
        };
        bytes_read += 2;
        let class = NetworkEndian::read_u16(&bytes[bytes_read..]);
        bytes_read += 2;
        let ttl = NetworkEndian::read_u32(&bytes[bytes_read..]);
        bytes_read += 4;
        let data_length = NetworkEndian::read_u16(&bytes[bytes_read..]);
        bytes_read += 2;
        let b = match qtype {
            ResourceType::NS | ResourceType::CName => {
                let (domain, num_read) = deserialize_domain_from_bytes(&packet_bytes, &bytes[bytes_read..]).unwrap();
                bytes_read += num_read;
                serialize_domain_to_bytes(&domain).to_vec()
            },
            ResourceType::AAAA => {
                let rdata = bytes[bytes_read..(bytes_read + data_length as usize)].to_vec();
                bytes_read += 6;
                rdata
            }
            _ => {
                let rdata = bytes[bytes_read..(bytes_read + data_length as usize)].to_vec();
                bytes_read += 4;
                rdata
            }
        };
        Ok((
            DnsAnswer {
                name,
                qtype,
                class,
                ttl,
                data_length: b.len() as u16,
                rdata: b,
            },
            bytes_read,
        ))
    }
}

impl ToBytes for DnsAnswer {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.append(&mut serialize_domain_to_bytes(&self.name));
        res.write_u16::<NetworkEndian>(self.qtype.as_u16()).unwrap(); // TODO don't unwrap, handle error, return error response
        res.write_u16::<NetworkEndian>(self.class).unwrap();
        res.write_u32::<NetworkEndian>(self.ttl).unwrap();
        res.write_u16::<NetworkEndian>(self.data_length).unwrap();
        res.append(&mut self.rdata.clone());
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_dns_answer_to_bytes() {
        let mut ans = DnsAnswer::new();
        ans.name = "foo.bar.com".to_owned();
        ans.qtype = ResourceType::A;
        ans.class = 0x0123;
        ans.ttl = 0x456789ab;
        ans.data_length = 4;
        ans.rdata = vec![0xde, 0xca, 0xfb, 0xad];
        let actual_bytes = ans.to_bytes();
        let expected_bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            0x01, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x00, 0x04, 0xde, 0xca, 0xfb, 0xad,
        ]
        .to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }

    #[test]
    fn test_dns_answer_from_bytes() {
        let bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            0x01, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x00, 0x04, 0xde, 0xca, 0xfb, 0xad,
        ];
        let mut expected_answer = DnsAnswer::new();
        expected_answer.name = "foo.bar.com".to_owned();
        expected_answer.qtype = ResourceType::A;
        expected_answer.class = 0x0123;
        expected_answer.ttl = 0x456789ab;
        expected_answer.data_length = 4;
        expected_answer.rdata = vec![0xde, 0xca, 0xfb, 0xad];
        let (actual_answer, _) = DnsAnswer::from_bytes(&vec![], &bytes).unwrap();
        assert_eq!(expected_answer, actual_answer);
    }

    #[test]
    fn test_from_bytes_and_to_bytes() {
        let expected_bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, 0x03, 0x62, 0x61, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            0x01, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x00, 0x04, 0xde, 0xca, 0xfb, 0xad,
        ];
        let (answer, num_read) = DnsAnswer::from_bytes(&vec![], &expected_bytes).unwrap();
        assert_eq!(expected_bytes.len(), num_read);
        assert_eq!(expected_bytes.to_vec(), answer.to_bytes());
    }
}
