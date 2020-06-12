/// This is a module to register custom domains on custom tlds
/// that are only available on this dns server (in that case
/// this is the authoritative dns server for that tld)

trait TldRepository {
    fn resolve(&self, fqdn: &str) -> String;
    fn create(&self, fqdn: &str) -> String;
}

/// This struct holds any information on local tlds and domains
/// registered under them. This information is stored in a local
/// json file
struct JsonTldRepository {
    //records: 
}

impl TldRepository for TldRepository {
    resolve(&self, fqdn: &str) -> String {
        "127.0.0.1".to_owned()
    }

    fn create(&self, fqdn: &str) -> String {
        "127.0.0.1".to_owned()
    }
}