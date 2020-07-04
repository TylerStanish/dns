use crate::header::ResourceType;


struct Record {
    rec_type: ResourceType,
}

struct SoaInformation {
    domain_name: String,
    fqdn: String,
    soa_email: String,
    serial: usize,
    refresh: usize,
    retry: usize,
    expire: usize,
    minimum: usize,
    nameservers: Vec<String>,
}
