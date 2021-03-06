use crate::header::{ResourceType, ResponseCode};
use crate::serialization::{
    deserialize_domain_from_bytes, serialize_domain_to_bytes, FromBytes, ToBytes,
};
use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use std::convert::TryInto;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: ResourceType,
    pub class: u16,
}

impl DnsQuery {
    pub fn new() -> Self {
        DnsQuery {
            name: String::new(),
            qtype: ResourceType::Unused,
            class: 1,
        }
    }

    /// Remember according to the rfc:
    /// 'each label consists of a length octet followed by that
    /// number of octets.  The domain name terminates with the
    /// zero length octet for the null label of the root.  Note
    /// that this field may be an odd number of octets; no
    /// padding is used.'
    pub fn from_bytes(packet_bytes: &[u8], bytes: &[u8]) -> Result<(Self, usize), Self> {
        //let ending = bytes.iter().position(|n| *n == 0).unwrap(); // TODO don't unwrap this, handle the bad input user gave us
        //println!("{:?}", std::str::from_utf8(&bytes[..ending]));

        let (name, curr_byte) = match deserialize_domain_from_bytes(&packet_bytes, &bytes) {
            Ok(tup) => tup,
            Err(_) => return Err(DnsQuery::new()),
        };
        let qtype = match NetworkEndian::read_u16(&bytes[curr_byte..curr_byte + 2]).try_into() {
            Ok(code) => code,
            Err(code) => return Err(DnsQuery::new()),
        };
        let class = NetworkEndian::read_u16(&bytes[curr_byte + 2..curr_byte + 4]);
        // resize the slice so the caller of this function can continue
        // and not have to do any arithmetic or handle a tuple return type
        // or extra pointer variable
        // UPDATE unfortunately, I don't know if there's a way to mutate a param
        // like this, even having `mut: &mut`
        Ok((DnsQuery { name, qtype, class }, curr_byte + 4))
    }
}

impl ToBytes for DnsQuery {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.append(&mut serialize_domain_to_bytes(&self.name));
        res.write_u16::<NetworkEndian>(self.qtype.as_u16()).unwrap();
        res.write_u16::<NetworkEndian>(self.class).unwrap();
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    /// mostly testing for endianness
    fn test_query_from_bytes() {
        let mut bytes = [
            0x03, // length of 'foo'
            0x66u8, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let (actual_query, _) = DnsQuery::from_bytes(&vec![], &mut bytes).unwrap();
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.com".to_owned();
        expected_query.qtype = ResourceType::A;
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
        let (actual_query, _) = DnsQuery::from_bytes(&vec![], &mut bytes).unwrap();
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.com".to_owned();
        expected_query.qtype = ResourceType::A;
        expected_query.class = 1;

        assert_eq!(expected_query, actual_query);
    }

    #[test]
    fn test_query_from_bytes_with_subdomain() {
        let mut bytes = [
            0x03u8, // length of 'foo'
            0x66, 0x6f, 0x6f, 0x03, // length of 'bar'
            0x62, 0x61, 0x72, 0x03, 0x63, 0x6f, 0x6d, 0x00, // foo.bar.com
            0x00, 0x01, // a record
            0x00, 0x01, // class
        ];
        let (actual_query, _) = DnsQuery::from_bytes(&vec![], &mut bytes).unwrap();
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.bar.com".to_owned();
        expected_query.qtype = ResourceType::A;
        expected_query.class = 1;

        assert_eq!(expected_query, actual_query);
    }

    #[test]
    fn test_dns_query_to_bytes() {
        let mut query = DnsQuery::new();
        query.name = "foo.bar.com".to_owned();
        query.qtype = ResourceType::AAAA;
        query.class = 0x0123;
        let actual_bytes = query.to_bytes();
        let expected_bytes = [
            0x03u8, 0x66u8, 0x6f, 0x6f, // foo
            0x03, 0x62, 0x61, 0x72, // bar
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
            0x00, 0x1c, 0x01, 0x23,
        ]
        .to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }
}
