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
OpenID4VP 1.0 alone. The plan pins three variants and lets you choose two:

| Variant | Value | |
|---|---|---|
| `VPProfile` | `haip` | fixed |
| `client_id_prefix` | `x509_hash` | fixed |
| `request_method` | `request_uri_signed` | fixed |
| `response_mode` | `direct_post` or `direct_post.jwt` | your choice |
| `credential_format` | `sd_jwt_vc` or `iso_mdl` | your choice |

The last two become part of the certification profile name, so **SD-JWT VC and mdoc are separate
certifications**. Start with `sd_jwt_vc` + `direct_post.jwt`, which is the HAIP default and already
Tessio's default.

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

Create the test plan in the suite UI, choose `oid4vp-1final-verifier-haip-test-plan`, pick your
`response_mode` and `credential_format`, and note the two values it gives you. Then:

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

Set `Request:CredentialFormat` and `Request:ResponseMode` in `appsettings.json` to **match the variants
you chose**. A mismatch fails the module for the wrong reason, and you will not see it until the
screenshot.

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
  refuses to start without them rather than producing twelve worthless results.
- **`dc+sd-jwt`**: depends on how the suite signs. Start with none, and if the modules reject with an
  untrusted issuer, export the suite's issuer certificate and list its path in `Suite:TrustAnchors`.
  PEM or DER both load.

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
| `Request:ResponseMode` | `DirectPostJwt` or `DirectPost`. Match the plan variant. |
| `Request:Claim` | Single claim to request. The suite requires DCQL to name exactly one credential. |
| `Request:ExpectedVct` | `urn:eudi:pid:1` for the suite's SD-JWT VC credential. |

The signing certificate is self-signed and generated per run. The suite checks that `client_id`'s hash
matches the leaf in `x5c`, not that the chain is publicly trusted, so no real access certificate is
needed and none should be put here.
