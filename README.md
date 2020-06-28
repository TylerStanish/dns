Features
  - Full packet (de)serialization
  - Record types
    - A
    - CNAME
    - SOA
  - Caching

TODOs
  - Jump directives/Pointer decompression
    - From RFC1035: 'Programs are free to avoid using pointers in messages they
      generate, ... However all programs are required to understand arriving
      messages that contain pointers.'
  - Multithreaded
  - Block-list for blocking websites
  - If the client asks for an A record for a domain, but and have a CNAME record for that domain, 
    which in turn has an a record for that domain, return the A record and the CNAME. Your home router does this
  - Authoritative (and recursive) server
  - Provide TLDs
  - Web dashboard/api

Extra Features:
  - IPv6 support?
  - DoH/DoT support?
