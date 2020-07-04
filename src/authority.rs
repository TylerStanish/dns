use std::fs::{create_dir, read_dir, read_to_string};
use std::io::ErrorKind;
use yaml_rust::{Yaml, YamlLoader};

use crate::record::{Record, SoaInformation};

pub struct Authority {
    default_ttl: usize,
    soa_record: Record,
    records: Vec<Record>,
}

impl Authority {
    pub fn new_from_yaml(yaml: &[Yaml]) -> Self {
        let soa = SoaInformation::from_yaml(&yaml[0]["soa-record"]);
        Authority {
            default_ttl: yaml[0]["ttl"].as_i64().expect("Invalid yaml file") as usize,
            soa_record: soa,
            records: ,
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
            },
            _ => panic!("An unexpected io error happened"),
        }
    };
    let mut auths = Vec::new();
    for auth in files {
        let os_file_name = auth.unwrap().file_name();
        let file_name = os_file_name.to_str().expect("We do not support your operating system");
        let yaml = YamlLoader::load_from_str(&read_to_string(file_name).unwrap()).expect(&format!("Invalid yaml in {}", file_name));
        auths.push(Authority::new_from_yaml(&yaml));
    }
    auths
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_new_from_yaml() {
        let input = "
            ttl: 60
        ";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        let authority = Authority::new_from_yaml(&yaml);
        assert_eq!(60, authority.default_ttl);
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
