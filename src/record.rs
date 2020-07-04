use std::convert::TryInto;

use crate::header::ResourceType;

use yaml_rust::Yaml;


pub struct Record {
    name: String,
    ttl: usize,
    rec_type: ResourceType,
    rec_class: ResourceType,
    data: Vec<u8>,
}

impl Record {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        Record {
            name: extract_string(yaml, "name").unwrap(),
            ttl: extract_integer(yaml, "ttl").unwrap() as usize,
            rec_type: extract_string(yaml, "type").unwrap().as_str().try_into().expect("Unsupported resource type"),
            rec_class: extract_string(yaml, "class").unwrap().as_str().try_into().expect("Unsupported class"),
            data: extract_string(yaml, "data").unwrap().bytes().collect::<Vec<u8>>(),
        }
    }
}

pub struct SoaInformation {
    domain_name: String,
    fqdn: String,
    email: String,
    serial: usize,
    refresh: usize,
    retry: usize,
    expire: usize,
    minimum: usize,
    nameservers: Vec<String>,
}

impl SoaInformation {
    pub fn from_yaml(yaml: &Yaml) -> Self {
        SoaInformation {
            domain_name: extract_string(yaml, "domain").unwrap(),
            fqdn: extract_string(yaml, "fqdn").unwrap(),
            email: extract_string(yaml, "email").unwrap(),
            serial: extract_integer(yaml, "email").unwrap() as usize,
            refresh: extract_integer(yaml, "refresh").unwrap() as usize,
            retry: extract_integer(yaml, "retry").unwrap() as usize,
            expire: extract_integer(yaml, "expire").unwrap() as usize,
            minimum: extract_integer(yaml, "minimum").unwrap() as usize,
            nameservers: ,
        }
    }
}

/// Will panic if the yaml at the key is not a integer
fn extract_integer(yaml: &Yaml, key: &str) -> Result<i64, ()> {
    match yaml[key] {
        Yaml::Integer(n) => Ok(n),
        _ => Err(()),
    }
}

/// Will panic if the yaml at the key is not a string
fn extract_string(yaml: &Yaml, key: &str) -> Result<String, ()> {
    match yaml[key] {
        Yaml::String(s) => Ok(s),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_record_from_yaml() {
        unimplemented!()
    }

    #[test]
    fn test_record_from_yaml_invalid() {
        unimplemented!()
    }

    #[test]
    fn test_soa_info_from_yaml() {
        unimplemented!()
    }

    #[test]
    fn test_soa_info_from_yaml_invalid() {
        unimplemented!()
    }
}