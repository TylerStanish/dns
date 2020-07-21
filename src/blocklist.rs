use std::env;
use std::fs::read_to_string;
use std::collections::HashMap;

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
        Some(p) => s.chars().nth(p),
        None => return Err("'*' must be followed by '.'".to_owned()),
    };
    if pos.unwrap() == s.len() - 2 {
        return Err("'*.' must not appear at end of entry".to_owned());
    }
    Ok((s[pos.unwrap()..].to_owned(), true))
}

pub fn load_blocklist() -> HashMap<String, bool> {
    let blocklist_file = env::var("BLOCKLIST_FILE").unwrap_or("blocklist.yml".to_owned());
    let yaml_arr = YamlLoader::load_from_str(&read_to_string(&blocklist_file).expect("Could not load blocklist file")).expect("Could not load blocklist yaml file");
    let mut res = HashMap::new();
    for yaml in yaml_arr {
        let s = match yaml {
            Yaml::String(s) => s,
            _ => panic!("The blocklist file can only a list of strings")
        };
        let (domain, contains_wildcard) = validate_blocklist_entry(&s).unwrap();
        res.insert(domain, contains_wildcard);
    };
    res
}