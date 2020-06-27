use crate::header::ResponseCode;
use crate::packet::DnsPacket;

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

pub fn deserialize_domain_from_bytes(bytes: &[u8]) -> (String, usize) {
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
            break;
        }
        name.push('.');
    }
    curr_byte += 1; // consume zero octet
    (name, curr_byte)
}

pub fn expand_pointers(packet_bytes: &[u8], name_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let mut res = Vec::new();
    let mut it = name_bytes.iter().enumerate();
    while let Some((idx, byte)) = it.next() {
    //for (idx, byte) in name_bytes.iter().enumerate() {
        println!("idx: {}, byte: {:x}, byte & 0xc0: {:x}", idx, byte, byte & 0xc0);
        if byte & 0xc0 == 0xc0 {
            let mut ptr = (byte & 0x3f) as u16;
            println!("after &: {}", ptr);
            ptr <<= 8;
            println!("after <<=: {}", ptr);
            if idx+1 >= name_bytes.len() {
                return Err(()) // compression flag was last byte in sequence
            }
            ptr += name_bytes[idx+1] as u16;
            println!("after +=: {}", ptr);
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
        let (actual_bytes, bytes_read) = deserialize_domain_from_bytes(&bytes);
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
        let (actual_bytes, bytes_read) = deserialize_domain_from_bytes(&bytes);
        assert_eq!("foo.bar.com", actual_bytes);
        assert_eq!(13, bytes_read);
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
            0x03u8, 0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x01, 0x23, 0x45,
        ];
        let third_bytes = [
            0xc0u8, 0x0c, 0x04, 0xde, 0xca, 0xfb, 0xad,
        ];
        let mut bytes = first_bytes.to_vec();
        bytes.append(&mut second_bytes.to_vec());
        bytes.append(&mut third_bytes.to_vec());
        let res = expand_pointers(&bytes, &third_bytes).unwrap();
        assert_eq!(second_bytes[..9].to_vec(), res);
    }
}
