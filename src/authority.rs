use std::fs::{create_dir, read_dir, read_to_string};
use std::io::ErrorKind;
use yaml_rust::{Yaml, YamlLoader};

pub struct Authority {

}

impl Authority {
    pub fn new_from_yaml(yaml: Vec<Yaml>) -> Self {
        unimplemented!();
        Authority {

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
        auths.push(Authority::new_from_yaml(yaml));
    }
    auths
}


#[cfg(test)]
mod tests {
    fn test_read_authority_file() {
        unimplemented!()
    }

    fn test_create_authorities_directory_if_absent() {
        unimplemented!()
    }
}
