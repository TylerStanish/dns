use std::collections::HashMap;
use crate::answer::DnsAnswer;
use crate::authority::authorities;
use crate::blocklist;
use crate::cache::Cache;
use crate::header::{ResourceType, ResponseCode};
use crate::packet::DnsPacket;
use crate::query::DnsQuery;
use crate::record::{RecordInformation, SoaInformation};
use crate::serialization::{
    deserialize_ipv4_from_str, deserialize_ipv6_from_str, serialize_domain_to_bytes, ToBytes,
};

pub struct DnsClient<'a, F>
where
    F: Fn(&str, DnsPacket) -> DnsPacket,
{
    resolver: F,
    cache: &'a mut Cache,
    blocklist: HashMap<String, bool>,
}

impl<'a, F> DnsClient<'a, F>
where
    F: Fn(&str, DnsPacket) -> DnsPacket,
{
    pub fn new(resolver: F, cache: &'a mut Cache) -> Self {
        DnsClient { resolver, cache, blocklist: blocklist::load_blocklist() }
    }

    /// Given `self` is a request packet, `results()` will return the packet
    /// to send back
    pub fn results(&self, req: DnsPacket) -> DnsPacket {
        match req.header.opcode {
            0 => self.standard_query(req),
            1 => self.inverse_query(req),
            _ => panic!(),
        }
    }

    fn standard_query(&self, req: DnsPacket) -> DnsPacket {
        let mut res = req.clone();
        if req.header.questions_count > 1 {
            // failed
            res.header.response_code = ResponseCode::NotImplemented;
            return res;
        }
        let mut answers: Vec<DnsAnswer> = Vec::new();
        let query = req.queries.first().unwrap();
        if self.cache.contains_key(&query) {
            answers.push(self.cache.get(&query).unwrap().clone());
            res.answers = vec![self.cache.get(&query).unwrap().clone()];
            res
        } else {
            // either we own the tld, or we need to get it
            let parts = query.name.split(".").collect::<Vec<&str>>();
            if parts.len() < 2 {
                // invalid domain
                res.header.response_code = ResponseCode::NameError;
                res.header.is_response = true;
                return res;
            }
            // check blocklist
            let tld = parts.last().unwrap();
            let auths = authorities();
            // check custom tlds
            for tld_match in auths
                .iter()
                .filter(|a| a.origin.split(".").last().unwrap_or("") == *tld)
            {
                for record in &tld_match.records {
                    let name = record.name.clone() + "." + &tld_match.origin;
                    if query.qtype == record.rec_type && query.name == name {
                        // we are the authority for this record
                        let mut ans = DnsAnswer::new();
                        ans.ttl = record.ttl;
                        ans.name = name;
                        ans.qtype = query.qtype.clone();
                        match &record.data {
                            RecordInformation::A(data) => {
                                ans.data_length = 4;
                                ans.rdata = deserialize_ipv4_from_str(&data);
                            }
                            RecordInformation::AAAA(data) => {
                                ans.data_length = 16;
                                ans.rdata = deserialize_ipv6_from_str(&data);
                            }
                            RecordInformation::CName(data) => {
                                ans.rdata = serialize_domain_to_bytes(data);
                                ans.data_length = ans.rdata.len() as u16;
                            }
                            RecordInformation::Soa(data) => {
                                ans.rdata = data.to_bytes();
                                ans.data_length = ans.rdata.len() as u16;
                            }
                        }
                        let mut res = DnsPacket::new_response();
                        res.header.authoritative = true;
                        res.header.answers_count = 1;
                        res.header.questions_count = 1;
                        res.header.tx_id = req.header.tx_id;
                        res.queries = req.queries;
                        res.answers = vec![ans];
                        return res;
                    }
                }
            }
            // check local authorities for the address, else go to the web
            let res = (self.resolver)("1.1.1.1", req);
            // TODO If we got any answers, return them. Else check any authoritative records
            // and recurse
            res
        }
    }

    fn inverse_query(&self, req: DnsPacket) -> DnsPacket {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use tempdir::TempDir;
    use ttl_cache::TtlCache;
    use yaml_rust::YamlLoader;

    #[test]
    fn accepts_single_question_only() {
        // Doesn't compile:
        // let client = DnsClient::new(|host: &str, req: DnsPacket| {req}, &mut TtlCache::new(0));
        let mut cache = TtlCache::new(0);
        let client = DnsClient::new(|_: &str, req: DnsPacket| req, &mut cache);
        let mut req = DnsPacket::new();
        req.header.questions_count = 2;
        let res = client.results(req);
        assert_eq!(res.header.response_code, ResponseCode::NotImplemented);
    }

    #[test]
    fn test_query_hits_cache() {
        let query = DnsQuery::new();
        let mut answer = DnsAnswer::new();
        answer.name = "12.34.56.78".to_owned();
        let mut cache = TtlCache::new(1);
        cache.insert(query.clone(), answer.clone(), Duration::from_secs(10));
        let client = DnsClient::new(|_: &str, req: DnsPacket| req, &mut cache);
        let mut req = DnsPacket::new();
        req.header.questions_count = 1;
        req.queries = vec![query];
        let res = client.results(req);
        assert_eq!(res.answers, vec![answer]);
    }

    #[test]
    fn test_gives_error_for_invalid_domain() {
        let mut query = DnsQuery::new();
        query.name = "invalid domain".to_owned();
        let mut cache = TtlCache::new(1);
        let client = DnsClient::new(|_: &str, req: DnsPacket| req, &mut cache);
        let mut req = DnsPacket::new();
        req.header.questions_count = 1;
        req.queries = vec![query];
        let res = client.results(req);
        assert_eq!(res.header.response_code, ResponseCode::NameError);
    }

    #[test]
    fn test_inverse_query() {
        unimplemented!()
    }

    #[test]
    fn test_authoritative_query() {
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
    name: baz
    data:
      domain: foo
      fqdn: soa.foo.com.
      email: foo@foo.com
      serial: 42
      refresh: 43
      retry: 44
      expire: 45
      minimum: 46
  - type: A
    class: IN
    ttl: 30
    name: baz
    data: 12.34.56.78
  - type: AAAA
    class: IN
    ttl: 30
    name: baz
    data: 2607:f8b0:4009:811::200e
  - type: CNAME
    class: IN
    ttl: 30
    name: baz
    data: bla.com
";
        authority_file.write_all(input).unwrap();

        // test A
        let mut query = DnsQuery::new();
        query.name = "baz.foo.com".to_owned();
        query.qtype = ResourceType::A;
        let mut req = DnsPacket::new();
        req.queries = vec![query.clone()];
        req.header.questions_count = 1;
        req.header.tx_id = 0xbeef;

        let mut cache = TtlCache::new(1);
        let client = DnsClient::new(|_, _| DnsPacket::new(), &mut cache);
        let actual_packet = client.standard_query(req);

        let mut expected_packet = DnsPacket::new_response();
        expected_packet.header.questions_count = 1;
        expected_packet.header.answers_count = 1;
        expected_packet.header.authoritative = true;
        expected_packet.header.tx_id = 0xbeef;
        let mut expected_answer = DnsAnswer::new();
        expected_answer.name = "baz.foo.com".to_owned();
        expected_answer.qtype = ResourceType::A;
        expected_answer.ttl = 30;
        expected_answer.data_length = 4;
        expected_answer.rdata = vec![0x0c, 0x22, 0x38, 0x4e];
        expected_packet.queries = vec![query];
        expected_packet.answers = vec![expected_answer];

        assert_eq!(expected_packet, actual_packet);

        // test AAAA
        let mut query = DnsQuery::new();
        query.name = "baz.foo.com".to_owned();
        query.qtype = ResourceType::AAAA;
        let mut req = DnsPacket::new();
        req.queries = vec![query.clone()];
        req.header.questions_count = 1;
        req.header.tx_id = 0xbeef;

        let actual_packet = client.standard_query(req);

        let mut expected_packet = DnsPacket::new_response();
        expected_packet.header.questions_count = 1;
        expected_packet.header.answers_count = 1;
        expected_packet.header.authoritative = true;
        expected_packet.header.tx_id = 0xbeef;
        let mut expected_answer = DnsAnswer::new();
        expected_answer.name = "baz.foo.com".to_owned();
        expected_answer.qtype = ResourceType::AAAA;
        expected_answer.ttl = 30;
        expected_answer.data_length = 16;
        expected_answer.rdata = vec![
            0x26, 0x07, 0xf8, 0xb0, 0x40, 0x09, 0x08, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x0e,
        ];
        expected_packet.queries = vec![query];
        expected_packet.answers = vec![expected_answer];

        assert_eq!(expected_packet, actual_packet);

        // test cname
        let mut query = DnsQuery::new();
        query.name = "baz.foo.com".to_owned();
        query.qtype = ResourceType::CName;
        let mut req = DnsPacket::new();
        req.queries = vec![query.clone()];
        req.header.questions_count = 1;
        req.header.tx_id = 0xbeef;

        let actual_packet = client.standard_query(req);

        let mut expected_packet = DnsPacket::new_response();
        expected_packet.header.questions_count = 1;
        expected_packet.header.answers_count = 1;
        expected_packet.header.authoritative = true;
        expected_packet.header.tx_id = 0xbeef;
        let mut expected_answer = DnsAnswer::new();
        expected_answer.name = "baz.foo.com".to_owned();
        expected_answer.qtype = ResourceType::CName;
        expected_answer.ttl = 30;
        expected_answer.rdata = serialize_domain_to_bytes("bla.com");
        expected_answer.data_length = expected_answer.rdata.len() as u16;
        expected_packet.queries = vec![query];
        expected_packet.answers = vec![expected_answer];

        assert_eq!(expected_packet, actual_packet);

        // test soa
        let mut query = DnsQuery::new();
        query.name = "baz.foo.com".to_owned();
        query.qtype = ResourceType::StartOfAuthority;
        let mut req = DnsPacket::new();
        req.queries = vec![query.clone()];
        req.header.questions_count = 1;
        req.header.tx_id = 0xbeef;

        let actual_packet = client.standard_query(req);

        let soa_yaml = "
domain: foo
fqdn: soa.foo.com.
email: foo@foo.com
serial: 42
refresh: 43
retry: 44
expire: 45
minimum: 46";
        let yaml = YamlLoader::load_from_str(soa_yaml).unwrap();
        let soa_information = SoaInformation::from_yaml(&yaml[0]);
        let mut expected_packet = DnsPacket::new_response();
        expected_packet.header.questions_count = 1;
        expected_packet.header.answers_count = 1;
        expected_packet.header.authoritative = true;
        expected_packet.header.tx_id = 0xbeef;
        let mut expected_answer = DnsAnswer::new();
        expected_answer.name = "baz.foo.com".to_owned();
        expected_answer.qtype = ResourceType::StartOfAuthority;
        expected_answer.ttl = 60;
        expected_answer.rdata = soa_information.to_bytes();
        expected_answer.data_length = expected_answer.rdata.len() as u16;
        expected_packet.queries = vec![query];
        expected_packet.answers = vec![expected_answer];

        assert_eq!(expected_packet, actual_packet);
    }
}
