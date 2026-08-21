# OpenID Foundation conformance harness

Runs Tessio.Verifier as the verifier under test against the OpenID Foundation's conformance suite,
which plays the wallet. Not part of the solution and never shipped: it exists to produce certification
evidence.

## Why HAIP, and why this matters

The suite publishes four OpenID4VP verifier test plans. Three say so in their own display name:
*"alpha version, may be incomplete or incorrect"* or *"not currently part of certification program"*.
The only one in the certification programme is:

```
oid4vp-1final-verifier-haip-test-plan
```

So certification means the **High Assurance Interoperability Profile**, which is stricter than
OpenID4VP 1.0 alone.

Queried from the running suite (`/api/plan/available`, 2026-08-10), not read off the source:

| Variant | Value | |
|---|---|---|
| `VPProfile` | `haip` | fixed |
| `client_id_prefix` | `x509_hash` | fixed |
| `request_method` | `request_uri_signed` | fixed |
| `response_mode` | `direct_post.jwt` | **only value offered** |
| `credential_format` | `sd_jwt_vc` or `iso_mdl` | your choice |

So the only real choice is the credential format, and it becomes part of the certification profile
name: **SD-JWT VC and mdoc are separate certifications**. Start with `sd_jwt_vc`.

The suite's variant names are not the wire format identifiers. `sd_jwt_vc` means
`Request:CredentialFormat = "dc+sd-jwt"` here, and `iso_mdl` means `"mso_mdoc"`.

The plan has exactly one configuration field, `client.request_object_trust_anchor_pem`. That is our
request-object signing certificate, which the harness prints on its landing page for copying and
persists between runs so the value you paste stays valid.

`x509_hash` is why `ClientIdentifier.X509Hash` exists. We shipped only `x509_san_dns` before this
work, which could not have been certified.

## What talks to what

Traffic runs opposite to normal testing. The suite is the wallet; we are the verifier.

```
you ──click start──▶ harness :5099
                        │  builds a JAR signed with its cert, stores it
                        ▼
             authorization URI ──▶ suite :8443  (the mock wallet)
                                      │  fetches http://host.docker.internal:5099/verify/request/{id}
                                      │  checks signature + that client_id's hash matches the x5c leaf
                                      │  mints a credential, signs it with its own key
                                      ▼
                        POST ──▶ http://host.docker.internal:5099/verify/callback
                                      │
                        harness verifies and records the outcome
                                      ▼
                        /evidence/{sessionId}  ← screenshot this
```

Two networking facts that otherwise cost an afternoon:

- The suite runs in Docker. `host.docker.internal` resolves **inside** the container but **not** on
  the host, so you browse `localhost:5099` while the suite must be told `host.docker.internal:5099`.
- **HTTPS is required**, for `request_uri` (JAR-5.2) and `response_uri` (OID4VP §8.2). A self-signed
  chain is enough: the suite installs a trust-all X509TrustManager and a `NoopHostnameVerifier`, so
  nothing needs adding to the container's truststore. Kestrel is configured in `Program.cs` from
  `PublicBaseUri`, so changing that one value moves both URIs.
- **The signing leaf must not be self-signed** (OID4VP §5.9.3). The harness mints a throwaway CA and
  issues the leaf from it, sending both in `x5c`. The **CA** is what goes in the plan's
  `client.request_object_trust_anchor_pem`; the **leaf** is what `client_id` hashes.
- The library derives `response_uri` from `Request.Host`, which is correct behind a proxy. There is no
  proxy here, so the harness rewrites the host to `PublicBaseUri` on every request. Without that,
  `response_uri` would be `localhost:5099`, which inside the container means the container itself: the
  wallet posts to itself, the session sits pending until it expires, and nothing in either log says why.

## Setup

Start the suite (no local Java build needed; the suite wants Java 21):

```sh
cd <wherever>/conformance-suite
docker compose -f docker-compose-prebuilt.yml up -d
# https://localhost:8443
```

Create the test plan in the suite UI, choose `oid4vp-1final-verifier-haip-test-plan` and your
`credential_format`, then note the authorization endpoint and issuer it gives you. Work through
"The order to do it in" below rather than this section alone, because the PEM has to go the other way
first. Then:

```sh
cd tools/conformance-harness
cat > appsettings.Local.json <<'JSON'
{
  "Suite": {
    "AuthorizationEndpoint": "https://localhost.emobix.co.uk:8443/test/a/<alias>/authorize",
    "Issuer": "https://localhost.emobix.co.uk:8443/test/a/<alias>/",
    "TrustAnchors": []
  }
}
JSON
dotnet run
```

`appsettings.Local.json` is gitignored. The harness refuses to start without both values rather than
guessing, because a wrong endpoint fails as a timeout twenty seconds later with no clue attached.

### Where key material lives

**Outside this working tree.** The harness signs with a self-signed certificate it generates per run,
and the private key must not sit in a git working tree at all. `.gitignore` would catch it, but an
ignore rule is one `git add -f`, one edited `.gitignore` or one tool that does not read `.gitignore`
away from failing. A file that is not in the tree cannot be committed.

Point the harness at wherever you keep it. Paths may be absolute or relative to this directory:

```json
{
  "Certificate": {
    "LeafPath":      "../../../tessio-verifier-local/conformance-harness/harness-leaf.pem",
    "KeyPath":       "../../../tessio-verifier-local/conformance-harness/harness-key.pem",
    "AuthorityPath": "../../../tessio-verifier-local/conformance-harness/harness-ca.pem"
  }
}
```

Omit the block entirely and the harness falls back to `harness-leaf.pem`, `harness-key.pem` and
`harness-ca.pem` in this directory. That still works and is still gitignored, but it puts a private key
one mistake away from a public repository. Prefer the explicit paths.

Set `Request:CredentialFormat` in `appsettings.json` to **match the variant you chose**. A mismatch
fails the module for the wrong reason, and you will not see it until the screenshot.

### Trust anchors, and the failure they prevent

`StaticTrustListResolver` trusts an issuer identifier outright only when the credential's key was
resolved from issuer metadata. When the key arrives in an `x5c` or `x5chain` header the identifier
proves nothing (anyone can put a name in a self-signed certificate), so the chain must anchor on a
certificate you configure, and **with no anchors configured every such credential is rejected**.

That failure is nastier than it sounds. The four positive modules fail outright, and the eight negative
modules *appear to pass* while actually rejecting for the wrong reason: the credential was refused over
trust configuration before the tampering under test could matter. The evidence page prints a warning
when a rejection carries an untrusted issuer, precisely so this does not reach a screenshot.

- **`mso_mdoc`**: anchors are mandatory, because mdoc trust is X.509 only (IACA roots). The harness
  refuses to start without them rather than producing worthless results. The OIDF suite signs every
  mdoc with a fixed, self-signed multipaz test certificate that is both Document Signer and IACA
  (subject `CN=certification.openid.net, O=OpenID Foundation`). Obtain it from the response's
  `x5chain`, or copy the PEM constant from the suite source
  (`src/main/kotlin/com/android/identity/testapp/TestAppUtils.kt`), save it as `suite-mdoc-iaca.pem`
  outside the repository (see "Where key material lives") and list its path in
  `Suite:TrustAnchors`. It rolls roughly annually
  (this one expires 2027-08-03); re-extract it when the positive modules begin rejecting on trust.
- **`dc+sd-jwt`**: depends on how the suite signs. Start with none, and if the modules reject with an
  untrusted issuer, export the suite's issuer certificate and list its path in `Suite:TrustAnchors`.
  PEM or DER both load.

## The order to do it in

The two ends need each other's values, so there is one unavoidable back and forth. This order gets it
in a single pass:

1. **Start the harness with placeholder suite values.** It only needs to boot far enough to print its
   certificate; the endpoint being wrong does not matter yet.
2. **Copy the PEM** from the landing page at <http://localhost:5099>.
3. **In the suite**, create the test plan: `oid4vp-1final-verifier-haip-test-plan`, choose
   `credential_format`, paste the PEM into `client.request_object_trust_anchor_pem`.
4. **Copy the suite's authorization endpoint and issuer** out of the created plan into
   `appsettings.Local.json`.
5. **Restart the harness.** The certificate persists, so the PEM you pasted in step 3 stays valid.
6. Run the modules.

## Running a module

1. Start the module in the suite.
2. Open <http://localhost:5099> and check the printed configuration matches the variants under test.
3. Click **Start a verification**. The browser follows the authorization URI to the suite.
4. Complete the flow there. The suite posts the presentation back.
5. Open `/evidence/{sessionId}` and screenshot it. Upload that to the module.

Each module finishes as **REVIEW**: the suite cannot decide for you, the screenshot is the evidence.

### The negative tests are the point

Eight of the twelve modules are negative: invalid session transcript, invalid key-binding JWT
signature, invalid credential signature, tampered `sd_hash`, wrong KB-JWT nonce, wrong KB-JWT audience,
`iat` in the past, `iat` in the future. **Rejecting is the pass.**

That is why `/evidence/{sessionId}` exists rather than reusing the library's built-in status page. The
built-in page prints "Verification failed" without the reason, which cannot distinguish "rejected the
tampered `sd_hash`, exactly as required" from "rejected because the trust list was misconfigured". The
evidence page prints the error codes and messages, the resolved issuer and its trust status, and the
disclosed claims.

## Certifying

Running the tests is free. Going on the record costs a fee to the OpenID Foundation. Run the whole
plan first and fix anything red before paying. See <https://openid.net/certification/> and
`certification@oidf.org`.

## Configuration reference

| Key | Meaning |
|---|---|
| `PublicBaseUri` | Where the suite reaches us. `http://host.docker.internal:5099` on Docker Desktop. |
| `Suite:AuthorizationEndpoint` | The suite's mock wallet endpoint, from the test plan. |
| `Suite:Issuer` | The suite's credential issuer, which we must trust. |
| `Request:CredentialFormat` | `dc+sd-jwt` or `mso_mdoc`. Match the plan variant. |
| `Request:ResponseMode` | `DirectPostJwt`. The HAIP plan offers no other value. |
| `Request:Claim` | Single claim to request. The suite requires DCQL to name exactly one credential. |
| `Request:ExpectedVct` | `urn:eudi:pid:1` for the suite's SD-JWT VC credential. |

The signing certificate is self-signed and generated per run. The suite checks that `client_id`'s hash
matches the leaf in `x5c`, not that the chain is publicly trusted, so no real access certificate is
needed and none should be put here.
