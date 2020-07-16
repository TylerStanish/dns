use crate::header::ResponseCode;
use crate::packet::DnsPacket;
use std::net::Ipv6Addr;
use std::str;

pub trait FromBytes: Sized {
    // for some reason, when the return type is Self, we
    // don't need `: Sized` but when it is like below (Self in a tuple), we do, ugh
    // We need the result here because we need to know if we need to exit early when parsing. We could
    // say, return 0 in the tuple but that's not as good as Result. Also we need this
    // to be able to keep the transaction id in the header as a response
    fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), Self>;
}

pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

pub fn serialize_domain_to_bytes(domain: &str) -> Vec<u8> {
    let mut res = Vec::new();
    let split: Vec<&str> = domain.split('.').collect();
    if split.len() > 1 {
        for word in split {
            res.push(word.len() as u8);
            res.append(&mut Vec::from(word.as_bytes().clone()));
        }
        res.push(0);
    }
    res
}

pub fn deserialize_domain_from_bytes(
    packet_bytes: &[u8],
    bytes: &[u8],
) -> Result<(String, usize), ()> {
    let name_len = bytes[0];
    // the domain might just be the pointer
    if name_len & 0xc0 == 0xc0 {
        return match expand_pointers(packet_bytes, bytes) {
            Ok(name_bytes) => {
                match deserialize_domain_from_bytes(packet_bytes, &name_bytes) {
                    Ok((s, _)) => return Ok((s, 2)),
                    Err(_) => return Err(()),
                };
            }
            Err(_) => Err(()),
        };
    }
    // otherwise the domain starts with some characters
    let mut name = String::with_capacity(name_len as usize);
    let mut curr_byte = 0;
    loop {
        let len = bytes[curr_byte];
        if len & 0xc0 == 0xc0 {
            match expand_pointers(&packet_bytes, &bytes[0..]) {
                Ok(name_bytes) => {
                    match deserialize_domain_from_bytes(packet_bytes, &name_bytes) {
                        Ok((s, _)) => name.push_str(&s),
                        Err(_) => return Err(()),
                    };
                }
                Err(_) => return Err(()),
            };
            curr_byte += 2;
            // bounds check
            // FIXME once we hit this point, we can assume we're done right?
            // That is, once we reach a pointer, that pointer will go until the
            // end?
            break;
        }
        curr_byte += 1; // consume the size byte
        for i in curr_byte..(curr_byte as u8 + len) as usize {
            name.push(bytes[i] as char);
        }
        curr_byte += len as usize;
        if bytes[curr_byte] == 0 {
            curr_byte += 1; // consume zero octet
            break;
        }
        name.push('.');
    }
    Ok((name, curr_byte))
}

pub fn expand_pointers(packet_bytes: &[u8], name_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let mut res = Vec::new();
    let mut it = name_bytes.iter().enumerate();
    while let Some((idx, byte)) = it.next() {
        if byte & 0xc0 == 0xc0 {
            let mut ptr = (byte & 0x3f) as u16;
            ptr <<= 8;
            if idx + 1 >= name_bytes.len() {
                return Err(()); // compression flag was last byte in sequence
            }
            ptr += name_bytes[idx + 1] as u16;
            it.next(); // skip the second byte in the compression flag
            while packet_bytes[ptr as usize] != 0 {
                res.push(packet_bytes[ptr as usize]);
                ptr += 1;
            }
            res.push(0);
            break;
        }
    }
    Ok(res)
}

pub fn deserialize_ipv4_from_str(s: &str) -> Vec<u8> {
    let mut res = Vec::with_capacity(4);
    for byte in s.split(".") {
        res.push(byte.parse().expect("Invalid ipv4 address"));
    }
    res
}

pub fn deserialize_ipv6_from_str(s: &str) -> Vec<u8> {
    let mut res = Vec::with_capacity(16);
    for segment in s
        .parse::<Ipv6Addr>()
        .expect(&format!("Invalid ipv6 address {}", s))
        .segments()
        .iter()
    {
        res.push(((segment & 0xff00) >> 8) as u8);
        res.push((*segment) as u8);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_domain_to_bytes() {
        let expected_bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, // foo
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
        ];
        let actual_bytes = serialize_domain_to_bytes("foo.com");
        assert_eq!(expected_bytes.to_vec(), actual_bytes);
    }

    #[test]
    fn test_serialize_domain_to_bytes_with_subdomain() {
        let expected_bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, // foo
            0x03, 0x62, 0x61, 0x72, // bar
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
        ];
        let actual_bytes = serialize_domain_to_bytes("foo.bar.com");
        assert_eq!(expected_bytes.to_vec(), actual_bytes);
    }

    #[test]
    fn test_deserialize_domain_from_bytes() {
        let bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, // foo
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
        ];
        let (actual_bytes, bytes_read) = deserialize_domain_from_bytes(&vec![], &bytes).unwrap();
        assert_eq!("foo.com", actual_bytes);
        assert_eq!(9, bytes_read);
    }

    #[test]
    fn test_deserialize_domain_from_bytes_with_subdomain() {
        let bytes = [
            0x03u8, 0x66, 0x6f, 0x6f, // foo
            0x03, 0x62, 0x61, 0x72, // bar
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
        ];
        let (actual_bytes, bytes_read) = deserialize_domain_from_bytes(&vec![], &bytes).unwrap();
        assert_eq!("foo.bar.com", actual_bytes);
        assert_eq!(13, bytes_read);
    }

    #[test]
    fn test_deserialize_domain_from_bytes_with_pointer() {
        let bytes = [
            0x00u8, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x03, 0x66, 0x6f, 0x6f, // foo
            0x03, 0x62, 0x61, 0x72, // bar
            0x03, 0x63, 0x6f, 0x6d, 0x00, // com
            0x03u8, 0x62, 0x61, 0x7a, // baz
            0xc0, 0x06,
        ];
        let (actual_bytes, bytes_read) =
            deserialize_domain_from_bytes(&bytes, &bytes[19..]).unwrap();
        assert_eq!(6, bytes_read);
        assert_eq!("baz.foo.bar.com", actual_bytes);

        let (actual_bytes, bytes_read) =
            deserialize_domain_from_bytes(&bytes, &bytes[23..]).unwrap();
        assert_eq!(2, bytes_read);
        assert_eq!("foo.bar.com", actual_bytes);
    }

    #[test]
    fn test_expand_pointers() {
        let first_bytes = [
            0x00u8, 0x00, // transaction id
            0x80, 0x00, // flags (standard query response)
            0x00, 0x00, // 0 questions
            0x00, 0x02, // 2 answers
            0x00, 0x00, 0x00, 0x00, // answers
        ];
        let second_bytes = [
            //foo.com
            0x03u8, 0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // extra pointers for fluff
            0x00, 0x1c, 0x01, 0x23, 0x45,
        ];
        let third_bytes = [0xc0u8, 0x0c, 0x04, 0xde, 0xca, 0xfb, 0xad];
        let mut bytes = first_bytes.to_vec();
        bytes.append(&mut second_bytes.to_vec());
        bytes.append(&mut third_bytes.to_vec());
        let res = expand_pointers(&bytes, &third_bytes).unwrap();
        assert_eq!(second_bytes[..9].to_vec(), res);
    }

    #[test]
    fn test_deserialize_ipv4_from_str() {
        let mut actual = deserialize_ipv4_from_str("1.2.3.4");
        assert_eq!(actual, vec![0x1, 0x2, 0x3, 0x4]);
        actual = deserialize_ipv4_from_str("12.34.56.78");
        assert_eq!(actual, vec![12, 34, 56, 78]);
    }

    #[test]
    fn test_deserialize_ipv6_from_str() {
        let actual = deserialize_ipv6_from_str("2607:f8b0:4009:811::200e");
        assert_eq!(
            actual,
            vec![
                0x26, 0x07, 0xf8, 0xb0, 0x40, 0x09, 0x08, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20, 0x0e
            ]
        );
    }
}
