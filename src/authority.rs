use std::fs::{create_dir, read_dir, read_to_string};
use std::io::ErrorKind;
use yaml_rust::{Yaml, YamlLoader};

use crate::record::{extract_string, Record, SoaInformation};

#[derive(Debug, PartialEq, Eq)]
pub struct Authority {
    default_ttl: usize,
    origin: String,
    records: Vec<Record>,
}

impl Authority {
    pub fn new() -> Self {
        Authority {
            default_ttl: 0,
            origin: String::new(),
            records: Vec::new(),
        }
    }

    pub fn new_from_yaml(yaml: &Yaml) -> Self {
        let mut records = Vec::new();
        match &yaml["records"] {
            Yaml::Array(arr) => {
                for record_yaml in arr {
                    records.push(Record::from_yaml(&record_yaml));
                }
            }
            _ => panic!("The 'records' field must be an array"),
        }
        Authority {
            default_ttl: yaml["ttl"].as_i64().expect("Invalid yaml file") as usize,
            origin: yaml["origin"].as_str().unwrap().to_owned(),
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
    fn test_authority_new_from_yaml() {
        let input =
"
ttl: 60
origin: foo.com
records:
  - type: SOA
    class: IN
    ttl: 60
    name: bar
    data:
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
        let actual_authority = Authority::new_from_yaml(&yaml[0]);
        let mut expected_authority = Authority::new();
        // we already test for this in another test so we can reuse it here
        let expected_soa_information = SoaInformation::from_yaml(&yaml[0]["records"][0]["data"]);
        expected_authority.default_ttl = 60;
        expected_authority.origin = "foo.com".to_owned();
        expected_authority.records.push(Record::new());
        expected_authority.records[0].name = "bar".to_owned();
        expected_authority.records[0].ttl = 60;
        expected_authority.records[0].rec_type = ResourceType::StartOfAuthority;
        expected_authority.records[0].data = RecordInformation::Soa(expected_soa_information);
        assert_eq!(expected_authority, actual_authority);
    }

    #[test]
    fn test_requires_one_soa_record() {
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
    /// See https://docs.cloud.oracle.com/en-us/iaas/Content/DNS/Reference/formattingzonefile.htm#example
    fn test_expands_domain_not_ending_in_dot() {
        unimplemented!();
    }

    #[test]
    fn test_prepends_domain_with_origin() {
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
