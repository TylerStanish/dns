use crate::answer::DnsAnswer;
use crate::query::DnsQuery;
use ttl_cache::TtlCache;

pub type Cache = TtlCache<DnsQuery, DnsAnswer>;
