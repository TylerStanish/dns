use std::env;
use std::fs::{create_dir, read_dir, read_to_string};
use std::io::ErrorKind;
use std::path::Path;

use yaml_rust::{Yaml, YamlLoader};

use crate::header::ResourceType;
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
        let authority = Authority {
            default_ttl: yaml["ttl"].as_i64().expect("Invalid yaml file") as usize,
            origin: yaml["origin"].as_str().unwrap().to_owned(),
            records,
        };
        authority.check_has_one_authority_record();
        authority
    }

    /// Panics if `self.records` does not have one and only one SOA record
    fn check_has_one_authority_record(&self) {
        let soa_count = self.records.iter().filter(|rec| rec.rec_type == ResourceType::StartOfAuthority).count();
        assert_eq!(1, soa_count);
    }
}

pub fn authorities() -> Vec<Authority> {
    let authority_dir = env::var("AUTHORITY_DIR").unwrap_or("authorities".to_owned());
    let files = match read_dir(&authority_dir) {
        Ok(files) => files,
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                create_dir(&authority_dir).expect("Could not create the authorities directory");
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
        let file_location = Path::new(&authority_dir).join(file_name);
        let yaml_arr = YamlLoader::load_from_str(&read_to_string(&file_location).unwrap())
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
    use std::io::Write;
    use std::fs::{create_dir, File, read_dir, remove_dir, remove_dir_all};
    use std::path::Path;
    use std::env;
    use tempdir::TempDir;
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
    #[should_panic]
    fn test_fails_with_two_soa_records() {
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
        Authority::new_from_yaml(&yaml[0]);
    }

    #[test]
    #[should_panic]
    fn test_fails_with_zero_soa_records() {
        let input =
"
ttl: 60
origin: foo.com
records: []
";
        let yaml = YamlLoader::load_from_str(input).unwrap();
        Authority::new_from_yaml(&yaml[0]);
    }

    #[test]
    fn test_authorities_with_real_files() {
        let temp_authorities_dir = TempDir::new("authorities").unwrap();
        let authority_file_path = temp_authorities_dir.path().join("authority1.yml");
        env::set_var("AUTHORITY_DIR", temp_authorities_dir.path());
        let mut authority_file = File::create(authority_file_path).unwrap();
        let input = b"
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
        authority_file.write_all(input).unwrap();
        let auths = authorities();
        let yaml = YamlLoader::load_from_str(std::str::from_utf8(input).unwrap()).unwrap();
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
        assert_eq!(auths, vec![expected_authority]);
    }

    #[test]
    fn test_create_authorities_directory_if_absent() {
        let authority_dir = env::var("AUTHORITY_DIR").unwrap_or("authorities".to_owned());
        read_dir(&authority_dir).expect_err("The authorities directory already exists");
        authorities();
        read_dir(&authority_dir).unwrap();
        // we want to use `remove_dir` instead of `remove_dir_all` because we expect the
        // `authorities` directory to be empty
        remove_dir(&authority_dir).unwrap();
    }
}
