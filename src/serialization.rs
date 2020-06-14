pub trait FromBytes: Sized { // for some reason, when the return type is Self, we
    // don't need `: Sized` but when it is like below (Self in a tuple), we do, ugh
    fn from_bytes(bytes: &[u8]) -> (Self, usize);
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