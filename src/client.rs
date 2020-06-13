use std::mem;
use std::net::UdpSocket;
use crate::answer::DnsAnswer;
use crate::cache::Cache;
use crate::query::DnsQuery;
use crate::packet::DnsPacket;
use crate::serialization::{FromBytes, ToBytes};


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
        DnsClient {
            resolver,
            cache,
        }
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
            res.header.response_code = 4;
            return res;
        }
        let mut answers: Vec<DnsAnswer> = Vec::new();
        let query = req.queries.first().unwrap();
        if self.cache.contains_key(&query) {
            // Old way?:
            // https://stackoverflow.com/a/46906516

            // DnsAnswer must derive Clone to be able to deref a reference
            answers.push(self.cache.get(&query).unwrap().clone());
        } else {
            // either we own the tld, or we need to get it
            let parts = query.name.split(".").collect::<Vec<&str>>();
            if parts.len() < 2 {
                // invalid domain
            }
            let tld = parts.last();
            // get the authoritative server for this tld
            let res = (self.resolver)("198.41.0.4", req);
        }
        res.answers = answers;
        res
    }

    fn inverse_query(&self, req: DnsPacket) -> DnsPacket {
        unimplemented!()
    }
}


#[cfg(test)]
mod tests {
    use ttl_cache::TtlCache;
    use super::*;

    #[test]
    fn accepts_single_question_only() {
        // Doesn't compile:
        // let client = DnsClient::new(|host: &str, req: DnsPacket| {req}, &mut TtlCache::new(0));
        let mut cache = TtlCache::new(0);
        let client = DnsClient::new(|host: &str, req: DnsPacket| {req}, &mut cache);
        let mut req = DnsPacket::new();
        req.header.questions_count = 2;
        let res = client.results(req);
        assert_eq!(res.header.response_code, 4);
    }
}