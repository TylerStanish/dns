use crate::answer::DnsAnswer;
use crate::authority::authorities;
use crate::cache::Cache;
use crate::header::ResponseCode;
use crate::packet::DnsPacket;
use crate::query::DnsQuery;
use crate::serialization::{FromBytes, ToBytes};
use std::mem;
use std::net::UdpSocket;

pub struct DnsClient<'a, F>
where
    F: Fn(&str, DnsPacket) -> DnsPacket,
{
    resolver: F,
    cache: &'a mut Cache,
}

impl<'a, F> DnsClient<'a, F>
where
    F: Fn(&str, DnsPacket) -> DnsPacket,
{
    pub fn new(resolver: F, cache: &'a mut Cache) -> Self {
        DnsClient { resolver, cache }
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
            let tld = parts.last().unwrap();
            let auths = authorities();
            // check custom tlds
            for tld_match in auths.iter().filter(|a| a.origin.split(".").last().unwrap_or("") == *tld) {
                for record in &tld_match.records {
                    if query.qtype == record.rec_type && query.name == tld_match.origin.clone() + &record.name {
                        // we are the authority for this record
                        let mut ans = DnsAnswer::new();
                        ans.ttl = record
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
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use tempdir::TempDir;
    use ttl_cache::TtlCache;

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

        let mut query = DnsQuery::new();
        query.name = "bar.foo.com".to_owned();
        let mut req = DnsPacket::new();
        req.queries = vec![query];
        req.header.questions_count = 1;
    }

    #[test]
    fn test_custom_ttl() {
        unimplemented!();
    }
}
