use std::convert::TryInto;

use yaml_rust::Yaml;

use crate::header::ResourceType;

#[derive(Debug, PartialEq, Eq)]
pub enum RecordInformation {
    A(String),
    AAAA(String),
    CName(String),
    Soa(SoaInformation),
}

impl RecordInformation {
    pub fn new_from_type_and_yaml(rec_type: ResourceType, yaml: &Yaml) -> Self {
        match rec_type {
            ResourceType::A => RecordInformation::A(extract_string(yaml, "").unwrap()),
            ResourceType::AAAA => RecordInformation::AAAA(extract_string(yaml, "").unwrap()),
            ResourceType::CName => RecordInformation::CName(extract_string(yaml, "").unwrap()),
            ResourceType::StartOfAuthority => RecordInformation::Soa(SoaInformation::from_yaml(&yaml)),
            _ => panic!("Unsupported resource type in record"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Record {
    name: String,
    ttl: usize,
    rec_type: ResourceType,
    rec_class: String, // should always be 'IN'
    // this needs to be strongly typed (and not just Vec<u8> because we need to serialize it
    // somehow and we don't want users of this to have to enter the raw bytes into the yaml config
    // file
    data: RecordInformation,
}

impl Record {
    pub fn new() -> Self {
        Record {
            name: String::new(),
            ttl: 0,
            rec_type: ResourceType::A,
            rec_class: "IN".to_owned(),
            data: RecordInformation::A("0.0.0.0".to_owned()),
        }
    }

    pub fn from_yaml(yaml: &Yaml) -> Self {
        let rec_type: ResourceType = extract_string(yaml, "type")
            .unwrap()
            .as_str()
            .try_into()
            .expect("Unsupported resource type");
        Record {
            name: extract_string(yaml, "name").unwrap(),
            ttl: extract_integer(yaml, "ttl").unwrap() as usize,
            rec_type: rec_type.clone(),
            rec_class: extract_string(yaml, "class").unwrap(),
            data: RecordInformation::new_from_type_and_yaml(rec_type, &yaml["data"]),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SoaInformation {
    domain_name: String,
    fqdn: String,
    email: String,
    serial: usize,
    refresh: usize,
    retry: usize,
    expire: usize,
    minimum: usize,
}

impl SoaInformation {
    pub fn new() -> Self {
        SoaInformation {
            domain_name: String::new(),
            fqdn: String::new(),
            email: String::new(),
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0,
        }
    }
    pub fn from_yaml(yaml: &Yaml) -> Self {
        SoaInformation {
            domain_name: extract_string(yaml, "domain").unwrap(),
            fqdn: extract_string(yaml, "fqdn").unwrap(),
            email: extract_string(yaml, "email").unwrap(),
            serial: extract_integer(yaml, "serial").unwrap() as usize,
            refresh: extract_integer(yaml, "refresh").unwrap() as usize,
            retry: extract_integer(yaml, "retry").unwrap() as usize,
            expire: extract_integer(yaml, "expire").unwrap() as usize,
            minimum: extract_integer(yaml, "minimum").unwrap() as usize,
        }
    }
}

fn extract_integer(yaml: &Yaml, key: &str) -> Result<i64, ()> {
    match yaml[key] {
        Yaml::Integer(n) => Ok(n),
        _ => Err(()),
    }
}

fn extract_string(yaml: &Yaml, key: &str) -> Result<String, ()> {
    let to_match = if key.is_empty() {
        &yaml
    } else {
        &yaml[key]
    };
    match to_match {
        Yaml::String(s) => Ok(s.clone()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yaml_rust::YamlLoader;

    #[test]
    fn test_record_from_yaml() {
        let input = "
            name: localhost
            ttl: 60
            class: IN
            type: A
            data: 127.0.0.1
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let actual_record = Record::from_yaml(&yaml[0]);
        let mut expected_record = Record::new();
        expected_record.name = "localhost".to_owned();
        expected_record.ttl = 60;
        expected_record.rec_class = "IN".to_owned();
        expected_record.rec_type = ResourceType::A;
        expected_record.data = RecordInformation::A("127.0.0.1".to_owned());
        assert_eq!(expected_record, actual_record);
    }

    #[test]
    fn test_soa_info_from_yaml() {
        let input = "
            domain: foo
            fqdn: soa.foo.com.
            email: foo@foo.com
            serial: 42
            refresh: 43
            retry: 44
            expire: 45
            minimum: 46
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let actual_authority_info = SoaInformation::from_yaml(&yaml[0]);
        let mut expected_authority_info = SoaInformation::new();
        expected_authority_info.domain_name = "foo".to_owned();
        expected_authority_info.fqdn = "soa.foo.com.".to_owned();
        expected_authority_info.email = "foo@foo.com".to_owned();
        expected_authority_info.serial = 42;
        expected_authority_info.refresh = 43;
        expected_authority_info.retry = 44;
        expected_authority_info.expire = 45;
        expected_authority_info.minimum = 46;
        assert_eq!(expected_authority_info, actual_authority_info);
    }
}
