use std::env;
use std::fs::{File, read_to_string};
use std::collections::HashMap;
use std::path::Path;

use yaml_rust::{Yaml, YamlLoader};

fn validate_blocklist_entry(s: &str) -> Result<(String, bool), String> {
    if !s.contains("*") {
        return Ok((s.to_owned(), false));
    }
    let pos = s.find("*.");
    if pos != s.rfind("*.") {
        // contained more than 1 '*.'
        return Err(format!("Blocklist entry contained more than one '*.': {}", s));
    }
    // strip wildcard
    match pos {
        Some(p) => s.chars().nth(p+2),
        None => return Err("'*' must be followed by '.'".to_owned()),
    };
    if pos.unwrap() == s.len() - 2 {
        return Err("'*.' must not appear at end of entry".to_owned());
    }
    Ok((s[(pos.unwrap()+2)..].to_owned(), true))
}

pub fn load_blocklist() -> HashMap<String, bool> {
    let filename = env::var("BLOCKLIST_FILE").unwrap_or("blocklist.yml".to_owned());
    if !Path::new(&filename).exists() {
        File::create(&filename).unwrap();
    }
    let yaml_arr = YamlLoader::load_from_str(&read_to_string(&filename).expect("Could not load blocklist file")).expect("Could not load blocklist yaml file");
    let mut res = HashMap::new();
    match &yaml_arr[0] {
        Yaml::Array(a) => for s in a {
            let blocked = match s {
                Yaml::String(s) => s,
                _ => panic!("The blocklist file can only be a list of strings"),
            };
            let (domain, contains_wildcard) = validate_blocklist_entry(&blocked).unwrap();
            res.insert(domain, contains_wildcard);
        },
        _ => panic!("The blocklist file can only be a list of strings"),
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_blocklist_entry() {
        validate_blocklist_entry("fdsa*.fdsa*.").unwrap_err();
        validate_blocklist_entry("abcd.*efgh").unwrap_err();
        validate_blocklist_entry("abcd*.").unwrap_err();
        assert_eq!(("foo.com".to_owned(), true), validate_blocklist_entry("*.foo.com").unwrap());
    }
}