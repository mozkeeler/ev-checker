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

Then, given the files `ee.pem` and `ca.pem`, the dotted OID of the EV policy,
and a description of the policy, run `ev-checker` like so:

`./ev-checker -e ee.pem -r ca.pem -o dotted.OID -d "OID description"`

`-e` specifies the end-entity certificate intended to be treated as an EV
certificate. `-r` specifies the root certificate that is authoritative for the
EV policy. NB: the handling of intermediates has not been implemented yet.
Ironically, this is a requirement for EV treatment.

`ev-checker` will output a blob of text that must be added to
`ExtendedVerification.cpp` in the mozilla-central tree for Firefox to consider
this a valid EV policy. It will also validate the end-entity certificate. If it
succeeds, the EV policy is ready to be enabled. If not, something needs to be
fixed. Hopefully `ev-checker` emitted a helpful error message pointing to the
problem.

## TODO Items ##
* Handle intermediate certificates
* Do OCSP fetching
* Other policy issues (e.g. require intermediates)
* More helpful error messages
