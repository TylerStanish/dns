use ttl_cache::TtlCache;
use crate::answer::DnsAnswer;
use crate::query::DnsQuery;

pub type Cache = TtlCache<DnsQuery, DnsAnswer>;