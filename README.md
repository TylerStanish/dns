TODOs
  - De-compression
    - From RFC1035: 'Programs are free to avoid using pointers in messages they
      generate, ... However all programs are required to understand arriving
      messages that contain pointers.'
  - Multithreaded
  - Block-list
  - If the client asks for an A record for a domain, but and have a CNAME record for that domain, 
    which in turn has an a record for that domain, return the A record and the CNAME. Your home router does this

Plans/Extra Features:
  - Better error handling!!!
  - Be both authoritative and recursive server
  - Provide TLDs
  - Ad blocking?
  - IPv6 support?
  - Jump directives?
  - TLS support?