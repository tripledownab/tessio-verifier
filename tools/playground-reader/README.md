# Reader certificate request

Material for requesting an **mdoc reader authentication certificate** from an interoperability
playground, so the verifier can be trusted by wallets in that environment.

A playground certificate is not a production relying-party access certificate. It does not enable
verification of production wallets; see `docs/production.md` for that path.

## Key handling

Some platforms offer to generate the private key for you. Generate it yourself instead, so only a CSR
crosses the wire.

**Keep the key outside this working tree.** The repo-wide `*.pem` ignore would catch it, but an ignore
rule is one `git add -f`, one edited `.gitignore` or one tool that does not read `.gitignore` away from
failing. A file that is not in the working tree cannot be committed at all. The CSR and its config carry
no secret and are tracked, so the request stays reproducible.

## Regenerating

Choose a directory outside the repository and keep the key there:

```sh
KEYDIR=../tessio-verifier-local/playground-reader   # anywhere outside this working tree
mkdir -p "$KEYDIR" && chmod 700 "$KEYDIR"

openssl ecparam -name prime256v1 -genkey -noout -out "$KEYDIR/reader-key.pem"
chmod 600 "$KEYDIR/reader-key.pem"
openssl req -new -key "$KEYDIR/reader-key.pem" -config reader-csr.cnf -out reader.csr
openssl req -in reader.csr -noout -text   # confirm the extensions below are present
```

The config requests what ISO/IEC 18013-5 Annex B.1.2 expects of a reader certificate:
`keyUsage = critical, digitalSignature` and `extendedKeyUsage = critical, 1.0.18013.5.1.6`
(mdlReaderAuth). A wallet may refuse a reader certificate without that EKU, so check the issued
certificate carries it before treating a failed presentation as a verifier defect.

## After issuance

Save the certificate next to the key, outside the repository, as `reader-cert.pem`. Note which trust
anchor it chains to: the wallet must trust that anchor, and the verifier needs the matching anchor
configured to validate the response. Wiring follows the conformance harness: the certificate goes in
the request object's `x5c`, and `client_id` is the `x509_hash` of the leaf.
