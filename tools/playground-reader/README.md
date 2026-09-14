# Reader certificate request

Material for requesting an **mdoc reader authentication certificate** from an interoperability
playground, so the verifier can be trusted by wallets in that environment.

A playground certificate is not a production relying-party access certificate. It does not enable
verification of production wallets; see `docs/production.md` for that path.

## The SAN decides whether the certificate is usable at all

**Set `READER_DNS` to the host in your `client_id` before generating anything.** OpenID4VP defines more
than one client identifier scheme, and which one you use decides what the certificate must carry:

| Scheme | client_id | What the certificate needs |
|---|---|---|
| `x509_san_dns` | `x509_san_dns:verifier.example.com` | That host in the **subjectAltName**. The wallet matches the two |
| `x509_hash` | `x509_hash:<base64url SHA-256 of the DER>` | Nothing extra. The identifier is the leaf itself |

A CSR with no SAN yields a certificate that looks right in every visible respect, with the correct key
usage and the correct reader EKU, and that every wallet refuses under `x509_san_dns`. Nothing surfaces
the mistake until a presentation fails. That is why `reader-csr.cnf` has no default for `READER_DNS` and
fails loudly when it is unset.

**Then check the issued certificate, not only the request.** A platform may ignore the SAN in your CSR
and issue without one:

```sh
openssl x509 -in reader-cert.pem -noout -text | grep -A1 "Alternative Name"
```

## Key handling

Some platforms offer to generate the private key for you. Generate it yourself instead, so only a CSR
crosses the wire. A form offering both "upload your own request" and "create one for you" is offering a
choice about who holds your private key. Take the first.

**Keep the key outside this working tree.** The repo-wide `*.pem` ignore would catch it, but an ignore
rule is one `git add -f`, one edited `.gitignore` or one tool that does not read `.gitignore` away from
failing. A file that is not in the working tree cannot be committed at all.

**The CSR belongs beside the key, not here.** `reader-csr.cnf` plus the environment below reproduces it
exactly, so committing one adds nothing, and a committed CSR is a file someone can submit without
checking whose values it carries or whether it names a SAN at all.

## Generating

Choose a directory outside the repository and keep both the key and the request there:

```sh
KEYDIR=/path/to/private-keys/playground-reader   # anywhere outside this working tree
mkdir -p "$KEYDIR" && chmod 700 "$KEYDIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$KEYDIR/reader-key.pem"
chmod 600 "$KEYDIR/reader-key.pem"

READER_CN="Example Verifier Reader" \
READER_ORG="Example Ltd" \
READER_COUNTRY="SE" \
READER_DNS="verifier.example.com" \
  openssl req -new -key "$KEYDIR/reader-key.pem" -config reader-csr.cnf -out "$KEYDIR/reader.csr"

openssl req -in "$KEYDIR/reader.csr" -noout -text   # confirm all four extensions below
```

The config requests what ISO/IEC 18013-5 Annex B.1.2 expects of a reader certificate:
`keyUsage = critical, digitalSignature` and `extendedKeyUsage = critical, 1.0.18013.5.1.6`
(mdlReaderAuth), plus the `subjectAltName` above. A wallet may refuse a reader certificate without that
EKU, so check the issued certificate carries it before treating a failed presentation as a verifier
defect.

## After issuance

Save the certificate next to the key, outside the repository, as `reader-cert.pem`.

**Verify it. Do not trust the issuer's "valid" badge.** A platform can issue happily and drop an
extension it did not understand, and a missing SAN under `x509_san_dns` then fails against every wallet
with nothing in any log to explain it. Four checks:

```sh
# 1. the SAN survived issuance, and the reader EKU with it
openssl x509 -in reader-cert.pem -noout -text | grep -A1 -e "Alternative Name" -e "Extended Key Usage"

# 2. it chains to the CA you expect
openssl verify -CAfile reader-ca.pem -purpose any reader-cert.pem

# 3. it belongs to the private key you hold
diff <(openssl x509 -in reader-cert.pem -noout -pubkey) \
     <(openssl ec -in "$KEYDIR/reader-key.pem" -pubout)

# 4. it is not already revoked
openssl crl -in reader-ca.crl -inform DER -noout -text | grep -A1 "Serial Number"
```

An issuer will normally add an Authority Key Identifier of its own. Seeing extensions you did not
request is expected; missing ones you did request are the problem.

**Record which trust anchor it chains to.** The wallet must trust that anchor, and the verifier needs the
matching anchor configured to validate the response. A playground usually publishes both the issuing
reader CA and the trusted list the certificate is added to; note both, because "the wallet does not
trust us" and "we do not trust the wallet's issuer" are different failures with the same symptom.

Wiring: the certificate goes in the request object's `x5c`, and the `client_id` states which scheme you
are using. The conformance harness in `tools/conformance-harness` uses `x509_hash`, so it needs no SAN.
A hosted verifier addressed by DNS will normally use `x509_san_dns`, which does. Pick one and make the
certificate match it.
