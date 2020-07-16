To run the tests, run `cargo test -- --test-threads 1`

Features
  - Full packet (de)serialization
  - Record types
    - A
    - CNAME
    - SOA
  - Caching
  - Jump directives/Pointer decompression
    - From RFC1035: 'Programs are free to avoid using pointers in messages they
      generate, ... However all programs are required to understand arriving
      messages that contain pointers.'
  - Provide TLDs
  - Authoritative (and recursive) server

Possible Extra Features:
  - Block-list for blocking websites
  - Web dashboard/api
  - Multithreaded
  - IPv6 support
  - DoH/DoT support
