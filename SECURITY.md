# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the
repository's **Security** tab and choose **Report a vulnerability**
(<https://github.com/Bunty9/ferryman-edge/security/advisories/new>). Do not
open a public issue for a suspected vulnerability.

You can expect an acknowledgement within 3 working days and an initial
assessment within 7 days. Confirmed issues are fixed in a patch release and
published as a GitHub Security Advisory with credit to the reporter, unless
you prefer otherwise.

## Supported versions

Until 1.0, only the latest minor release (currently 0.2.x) receives
security fixes.

## Notes for older releases

- **0.1.x and RUSTSEC-2026-0382.** The `Cargo.lock` shipped with 0.1.0–0.1.3
  pins `rustls-webpki` 0.103.15, which may accept distrusted intermediates
  when verifying certificates; ferryman-edge uses it to verify mTLS client
  certificates. 0.2.0 ships 0.103.16. If you cannot upgrade, install 0.1.3
  without `--locked` (Cargo then resolves a fixed `rustls-webpki`), or run
  `cargo update -p rustls-webpki` before building from source.
