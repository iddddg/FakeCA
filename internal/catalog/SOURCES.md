# Public certificate provenance

Retrieved 2026-10-27. Only public X.509 certificates are stored here; no private CA key files are bundled.

The eight `EM-*-CA-G3[B,C].crt.pem` certificates are from Wayne's original public attestation attachment on [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449):

- https://bugzilla.mozilla.org/attachment.cgi?id=9664066
- The eight `*-AAA.crt.pem` versions are from https://bugzilla.mozilla.org/attachment.cgi?id=9664067

The incident certificate DER SHA-256 fingerprints in `catalog.go` are pinned against the original incident disclosure. PEM whitespace does not affect these fingerprints. No attestation message or signature file is redistributed.

Parent certificates:

| Embedded file | Official source |
|---|---|
| `root-tls-self.pem` | https://repository.emsign.com/certs/EMDVTLSCAG3B.p7c (certificate-only PKCS#7) |
| `root-cs-self.pem` | https://repository.emsign.com/certs/EMOVCSCAG3B.p7c (certificate-only PKCS#7) |
| `root-tls-cross.pem` | https://repository.emsign.com/certs/crosssign/roottlscag3.crt |
| `root-cs-cross.pem` | https://repository.emsign.com/certs/crosssign/rootcscag3.crt |
| `root-ecc.pem` | https://repository.emsign.com/certs/emSignECCRootCAG3.crt |
| `root-aaa.pem` | http://crt.sectigo.com/AAACertificateServices.crt |

Root fingerprints are pinned against the [official emSign repository](https://repository.emsign.com/) and the Sectigo AAA public root fingerprint. The AAA download is HTTP, so the pinned DER hash and chain signatures are essential. All non-anchor links are checked cryptographically when the catalog is loaded. The pinned AAA anchor's historical SHA-1 self-signature is not used as a path signature; the program does not globally enable weak signature algorithms.

The code embeds 16 incident intermediate certificates plus six parent/root certificates. `list` reports 24 path combinations because native and ECC paths share their first intermediate.
