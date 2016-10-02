# ev-checker #
******

## What ##
`ev-checker` is a standalone command-line utility for determining if a given EV
policy fulfills the requirements of Mozilla's Root CA program and may thus be
enabled.

## How ##
`ev-checker` depends on the libraries
[NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) and
[NSPR](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR). It
additionally makes use of
[mozilla::pkix](https://wiki.mozilla.org/SecurityEngineering/Certificate_Verification).
Since mozilla::pkix has not been released as a stand-alone library yet, this
project imports a snapshot of the implementation. (See the file `pkix-import`.)
`ev-checker` implements a `mozilla::pkix::TrustDomain` and uses
`mozilla::pkix::BuildCertChain` to determine if a given EV policy meets the
requirements to be enabled in Firefox.

## Example ##
First, compile with `make`. There is no guarantee of portability, so feel free
to file issues if this does not work as expected.

Then, given the file `cert-chain.pem`, the dotted OID of the EV policy, and a
description of the policy, run `ev-checker` like so:

`./ev-checker -c cert-chain.pem -r ca.pem -o dotted.OID -d "OID description"`

`-c` specifies the file containing a sequence of PEM-encoded certificates. The
first certificate is the end-entity certificate intended to be tested for EV
treatment. The last certificate is the root certificate that is authoritative
for the given EV policy. Any certificates in between are intermediate
certificates.

`ev-checker` will output a blob of text that must be added to
`ExtendedVerification.cpp` in the mozilla-central tree for Firefox to consider
this a valid EV policy. It will also validate the end-entity certificate. If it
succeeds, the EV policy is ready to be enabled. If not, something needs to be
fixed. Hopefully `ev-checker` emitted a helpful error message pointing to the
problem.

```bash
$ ev-checker -c chain.pem -o 2.16.840.1.114412.2.1 -d "Digicert EV OID" -h addons.mozilla.org

// CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
"2.16.840.1.114412.2.1",
"Digicert EV OID",
SEC_OID_UNKNOWN,
{ 0xFD, 0xC8, 0x98, 0x6C, 0xFA, 0xC4, 0xF3, 0x5F, 0x1A, 0xCD, 0x51, 
  0x7E, 0x0F, 0x61, 0xB8, 0x79, 0x88, 0x2A, 0xE0, 0x76, 0xE2, 0xBA, 
  0x80, 0xB7, 0x7B, 0xD3, 0xF0, 0xFE, 0x5C, 0xEF, 0x88, 0x62 },
"MGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT"
"EHd3dy5kaWdpY2VydC5jb20xKzApBgNVBAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJh"
"bmNlIEVWIFJvb3QgQ0E=",
"ApcHVgzUqeu/4nLx4JbYgg==",
BuildCertChain failed: SEC_ERROR_UNKNOWN_ISSUER
Peer's Certificate issuer is not recognized.
```

## TODO Items ##
* Do OCSP fetching
* Other policy issues
* More helpful error messages
