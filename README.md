To run the tests, run `cargo test -- --test-threads 1`
To run the server, run `cargo run`

Environment Variables:
- `BLOCKLIST_FILE` the path to a blocklist file (if any)
- `AUTHORITY_DIR` the directory where yaml zone files can be found

An example blocklist file
```
- *.google.com
- bar.foo.com
```

An example of an authority file
```yaml
ttl: 60
origin: customdomain.customtld
records:
  - type: SOA
    class: IN
    ttl: 60
    name: soa
    data:
      domain: foo
      fqdn: soa.customdomain.customtld
      email: foo@customdomain.customtld
      serial: 42
      refresh: 43
      retry: 44
      expire: 45
      minimum: 46
  - type: A
    class: IN
    ttl: 10
    name: foo
    data: 12.34.56.78
  - type: MX
    class: IN
    ttl: 2000
    name: mail
    data:
      preference: 2
      exchange: foo.customdomain.customtld
```

Features
  - Full packet (de)serialization
  - Record types
    - A
    - AAAA
    - CNAME
    - SOA
    - MX
  - Caching
  - Jump directives/Pointer decompression
    - From RFC1035: 'Programs are free to avoid using pointers in messages they
      generate, ... However all programs are required to understand arriving
      messages that contain pointers.'
  - Provide TLDs
  - Authoritative and recursive server
  - Block-list for blocking websites

Possible Extra Features:
  - Web dashboard/api
  - Multithreaded
  - IPv6 support
  - DoH/DoT support
