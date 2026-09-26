package tools

// The captured output of:
//
//	nmap -p 443 --script ssl-cert,ssl-enum-ciphers -Pn -n example.com
//
// This is verbatim, including the "| " script-output prefixes, because the
// prefix is part of what a parser has to strip. A hand-written fixture with the
// prefixes already removed would pass against a parser that cannot read the
// real thing — which is exactly the bug this file replaced.
const nmapTLSOutput = `Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-26 15:30 +0300
Nmap scan report for example.com (8.6.112.0)
Host is up (0.030s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
|       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: server
|   TLSv1.1: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
|     compressors: 
|       NULL
|     cipher preference: server
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
|     compressors: 
|       NULL
|     cipher preference: client
|   TLSv1.3: 
|     ciphers: 
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (X25519MLKEM768) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (X25519MLKEM768) - A
|     cipher preference: client
|_  least strength: C
| ssl-cert: Subject: commonName=example.com
| Subject Alternative Name: DNS:example.com, DNS:*.example.com
| Issuer: commonName=Cloudflare TLS Issuing ECC CA 3/organizationName=SSL Corporation/countryName=US
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2026-07-29T22:10:08
| Not valid after:  2026-10-27T22:17:21
| MD5:     2545 353b 6cf7 ecf9 def9 b936 3dc0 2dfc
| SHA-1:   85dc 256a a794 31b0 190f 9c59 2b90 c2e8 e3b5 9b3e
|_SHA-256: 6153 a96f d1a6 ab7f 4d43 8fc3 4932 4842 99d0 729d 9140 b3a1 26bb 2f9c 07b0 2200

Nmap done: 1 IP address (1 host up) scanned in 13.14 seconds
`

// A modern, correctly configured endpoint, for the negative case.
const nmapTLSOutputModern = `443/tcp open  https
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
|     cipher preference: client
|   TLSv1.3: 
|     ciphers: 
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (X25519MLKEM768) - A
|     cipher preference: client
|_  least strength: A
| ssl-cert: Subject: commonName=modern.example
| Subject Alternative Name: DNS:modern.example
| Issuer: commonName=Modern CA/organizationName=Test
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2026-01-01T00:00:00
| Not valid after:  2027-01-01T00:00:00
`

// An endpoint offering only obsolete protocol versions.
const nmapTLSOutputObsolete = `443/tcp open  https
| ssl-enum-ciphers: 
|   SSLv2: 
|     ciphers: 
|       SSL_CK_RC4_128_WITH_MD5 - B
|   SSLv3: 
|     ciphers: 
|       TLS_RSA_WITH_RC4_128_SHA - B
|   TLSv1.0: 
|     ciphers: 
|       TLS_RSA_WITH_AES_128_CBC_SHA - A
|     compressors: 
|       NULL
|_  least strength: B
| ssl-cert: Subject: commonName=old.example
| Issuer: commonName=old.example
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2010-01-01T00:00:00
| Not valid after:  2012-01-01T00:00:00
`
