use byteorder::{ByteOrder, NetworkEndian, WriteBytesExt};
use resize_slice::ResizeSlice;
use crate::serialization::{deserialize_domain_from_bytes, serialize_domain_to_bytes, FromBytes, ToBytes};

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct DnsQuery {
    pub name: String,
    pub qtype: u16,
    pub class: u16,
}

impl DnsQuery {
    pub fn new() -> Self {
        DnsQuery {
            name: String::new(),
            qtype: 0,
            class: 0,
        }
    }

}

impl FromBytes for DnsQuery {
    /// This function modifies the `bytes` parameter so the caller of this
    /// function can continue off at the slice's zero index
    ///
    /// Remember according to the rfc:
    /// 'each label consists of a length octet followed by that
    /// number of octets.  The domain name terminates with the
    /// zero length octet for the null label of the root.  Note
    /// that this field may be an odd number of octets; no
    /// padding is used.'
    fn from_bytes(bytes: &[u8]) -> (Self, usize) {
        //let ending = bytes.iter().position(|n| *n == 0).unwrap(); // TODO don't unwrap this, handle the bad input user gave us
        //println!("{:?}", std::str::from_utf8(&bytes[..ending]));

        let (name, curr_byte) = deserialize_domain_from_bytes(&bytes);
        let qtype = NetworkEndian::read_u16(&bytes[curr_byte..curr_byte+2]);
        let class = NetworkEndian::read_u16(&bytes[curr_byte+2..curr_byte+4]);
        // resize the slice so the caller of this function can continue
        // and not have to do any arithmetic or handle a tuple return type
        // or extra pointer variable
        // UPDATE unfortunately, I don't know if there's a way to mutate a param
        // like this, even having `mut: &mut`
        (DnsQuery {
            name,
            qtype,
            class,
        }, curr_byte+4)
    }
}

impl ToBytes for DnsQuery {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.append(&mut serialize_domain_to_bytes(&self.name));
        res.write_u16::<NetworkEndian>(self.qtype).unwrap();
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
        let (actual_query, _) = DnsQuery::from_bytes(&mut bytes);
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
        let (actual_query, _) = DnsQuery::from_bytes(&mut bytes);
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
        let (actual_query, _) = DnsQuery::from_bytes(&mut bytes);
        let mut expected_query = DnsQuery::new();
        expected_query.name = "foo.bar.com".to_owned();
        expected_query.qtype = 1;
        expected_query.class = 1;

        assert_eq!(expected_query, actual_query);
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
            0x03u8, 0x66u8, 0x6f, 0x6f, // foo
            0x03, 0x62, 0x61, 0x72, // bar
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
            0xab, 0xcd,
            0x01, 0x23,
        ].to_vec();
        assert_eq!(expected_bytes, actual_bytes);
    }
}