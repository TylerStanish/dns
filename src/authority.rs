use std::fs::{create_dir, read_dir, read_to_string};
use std::io::ErrorKind;
use yaml_rust::{Yaml, YamlLoader};

use crate::record::{Record, SoaInformation};

#[derive(Debug, PartialEq, Eq)]
pub struct Authority {
    default_ttl: usize,
    soa_record: Record,
    records: Vec<Record>,
}

impl Authority {
    pub fn new() -> Self {
        Authority {
            default_ttl: 0,
            soa_record: Record::new(),
            records: Vec::new(),
        }
    }

    pub fn new_from_yaml(yaml: &Yaml) -> Self {
        let soa_info = SoaInformation::from_yaml(&yaml[0]["soa-record"]);
        let mut soa_record = Record::from_yaml(yaml);
        let mut records = Vec::new();
        match &yaml[0]["records"] {
            Yaml::Array(arr) => {
                for record_yaml in arr {
                    records.push(Record::from_yaml(&record_yaml));
                }
            }
            _ => panic!("The 'records' field must be an array"),
        }
        Authority {
            default_ttl: yaml[0]["ttl"].as_i64().expect("Invalid yaml file") as usize,
            soa_record,
            records,
        }
    }
}

pub fn authorities() -> Vec<Authority> {
    let files = match read_dir("authorities") {
        Ok(files) => files,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                create_dir("authorities").expect("Could not create the authorities directory");
                return authorities();
            }
            _ => panic!("An unexpected io error happened"),
        },
    };
    let mut auths = Vec::new();
    for auth in files {
        let os_file_name = auth.unwrap().file_name();
        let file_name = os_file_name
            .to_str()
            .expect("We do not support your operating system");
        let yaml_arr = YamlLoader::load_from_str(&read_to_string(file_name).unwrap())
            .expect(&format!("Invalid yaml in {}", file_name));
        for yaml in yaml_arr {
            auths.push(Authority::new_from_yaml(&yaml));
        }
    }
    auths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::ResourceType;
    use crate::record::RecordInformation;

    #[test]
    fn test_authority_new_from_yaml_no_records() {
        let input = "
            ttl: 60
            soa-record:
                domain: foo
                fqdn: soa.foo.com.
                email: foo@foo.com
                serial: 42
                refresh: 43
                retry: 44
                expire: 45
                minimum: 46
            records: []
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let actual_authority = Authority::new_from_yaml(&yaml[0]);
        let mut expected_authority = Authority::new();
        let expected_soa_information = SoaInformation::from_yaml(&yaml[0]["soa-record"]);
        expected_authority.default_ttl = 60;
        expected_authority.soa_record.name = "foo".to_owned();
        expected_authority.soa_record.ttl = 60;
        expected_authority.soa_record.rec_type = ResourceType::StartOfAuthority;
        expected_authority.soa_record.data = RecordInformation::Soa(expected_soa_information);
        assert_eq!(expected_authority, actual_authority);
    }

    #[test]
    fn test_authority_new_from_yaml() {
        let input = "
            ttl: 60
            soa-record:
                domain: foo
                fqdn: soa.foo.com.
                email: foo@foo.com
                serial: 42
                refresh: 43
                retry: 44
                expire: 45
                minimum: 46
            records: []
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let authority = Authority::new_from_yaml(&yaml[0]);
        assert_eq!(60, authority.default_ttl);
        unimplemented!();
    }

    #[test]
    fn test_authorities_with_many() {
        let input = "
            ttl: 60
            soa-record:
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let authority = Authority::new_from_yaml(&yaml[0]);
        assert_eq!(60, authority.default_ttl);
        unimplemented!();
    }

    #[test]
    fn test_authorities_with_real_files() {
        let input = "
            ttl: 60
            soa-record:
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let authority = Authority::new_from_yaml(&yaml[0]);
        assert_eq!(60, authority.default_ttl);
        unimplemented!();
    }

    #[test]
    fn test_read_authority_file() {
        unimplemented!()
    }

    #[test]
    fn test_create_authorities_directory_if_absent() {
        unimplemented!()
    }
}
