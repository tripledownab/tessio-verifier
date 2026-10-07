# Going live

How to take a Tessio.Verifier app from the built-in Demo, Mock and Test modes to real wallets.

The built-in modes exist so you can build and test without a wallet. Going live means four things change: the mode, the request signature, the trust list and the session store. Each is a service you register before `AddTessioVerifier`, which uses `TryAdd` for everything and therefore keeps whatever you registered first. Response encryption (§6) needs no change for a single instance and one deliberate design choice when you scale out.

```csharp
builder.Services.AddSingleton<IPresentationRequestBuilder>(...);   // 2. signed requests
builder.Services.AddSingleton<ITrustListResolver>(...);            // 3. real trust list
builder.Services.AddSingleton<ISessionStore>(...);                 // 4. shared sessions (multi-instance)
builder.Services.AddSingleton(new ResponseEncryptionKeyProvider(...)); // 5. shared decryption key (multi-instance)

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;                              // 1. no built-in actor completes sessions
    options.ClientId = "x509_san_dns:verifier.example.com";
    options.ExpectedVct = "urn:eudi:pid:1";
    options.RequestedClaims = ["age_over_18"];
});
```

A single-instance deployment only needs steps 1 to 3. Steps 4 and 5 matter once you scale past one process.

### Accepting more than one credential type

`options.ExpectedVct` asks for exactly one type. To accept several, pass a list to `Dcql.SdJwtVc` and drive the session yourself (see [self-driving-and-multi-tenant.md](self-driving-and-multi-tenant.md)):

```csharp
var options = new PresentationRequestOptions
{
    ClientId = "x509_san_dns:verifier.example.com",
    Nonce = /* per request, cryptographically random */,
    DcqlQueryJson = Dcql.SdJwtVc(["urn:eudi:pid:1", "urn:eudi:pid:de:1"], "age_over_18"),
    ResponseUri = new Uri("https://verifier.example.com/verify/callback"),
};
```

OpenID4VP 1.0 §B.3.5 defines `vct_values` as "a non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential". The verifier reads that whole array back out of the session's own request and accepts a credential whose `vct` is any member, per §8.6: "validate that the returned Credential(s) meet all criteria defined in the query".

Matching is exact, so list every type you accept. A credential that only *inherits* from a listed type is refused, because following SD-JWT VC type inheritance needs Type Metadata that this verifier does not retrieve.

**The single-claim form above names a claim the PID rulebook does not define, and that is deliberate
as an illustration but wrong as a starting point.** The EU PID Rulebook removed its age verification
attributes at version 1.1, 4 September 2025, "following CIR 2024/2977", and **read at version 1.7 of
17 July 2026 it still defines none**, so a conformant `urn:eudi:pid:1` carries no top-level
`age_over_18`. Both the version read and the version that changed are given because a rulebook this
young moves: v1.6 of 1 July 2026 is itself "Aligning with updated CIR 2024/2977", so confirm the
attribute list against the current document rather than against this sentence. Its §4.2 does let a
domestic type add claims, so
`urn:eudi:pid:de:1` may carry one, and whether it does is a question about that type rather than
about this API.

That matters more than a wrong attribute name, because of what happens next. §6.4.1: "If `claims` is
present, but `claim_sets` is absent, the Verifier requests all claims listed in `claims`", and the
wallet "MUST NOT return any claims" when it can satisfy none of them. So a single unsatisfiable claim
does not degrade to a partial answer. It returns nothing, which reads on the wallet as a missing
credential and on the verifier as a holder who declined.

Ask for the alternatives and say which you prefer, as the next section does.

### When those types put the same fact in different places

Listing several types is only half the problem. Two credential types can carry the same fact under
different claim names, or at different depths, and a query that names one claim finds nothing in the
other.

The base PID type carries a date of birth as `birthdate` and no age boolean at all: its rulebook removed
the age verification attributes in version 1.1, following CIR 2024/2977. A domestic type may still carry
one, and may express it as thresholds nested inside a single object rather than as separate top-level
booleans. Note the direction before assuming a national type invented its own shape: the age
attributes were in the base rulebook and were taken OUT of it, so a domestic type carrying one may
simply have kept it. Germany is the case this was written against; whether other member states did the
same is not something this page has checked.

So a query that accepts both types has to ask for both shapes and say which answer it prefers.
`Dcql.SdJwtVcByPath` addresses each claim by path, and `claim_sets` orders the alternatives:

```csharp
DcqlQueryJson = Dcql.SdJwtVcByPath(
    ["urn:eudi:pid:1", "urn:eudi:pid:de:1"],
    [
        new DcqlClaim { Id = "age18", Path = ["age_over_18"] },
        new DcqlClaim { Id = "age18nested", Path = ["age_equal_or_over", "18"] },
        new DcqlClaim { Id = "dob", Path = ["birthdate"] },
    ],
    ["age18"],        // a top-level boolean, if the credential has one
    ["age18nested"],  // the same answer nested, if it has that instead
    ["dob"]),         // and only failing both, the date of birth
```

**The order is the privacy decision, and the specification asks for it by name.** §6.4.1: "Verifiers
SHOULD use the principle of least information disclosure to influence how they order these options. For
example, a proof of age request should prioritize requesting an attribute like `age_over_18` over an
attribute like `birth_date`." The same section says the wallet SHOULD return the first option it can
satisfy and MUST NOT return any claims if it can satisfy none. Put `dob` first and every holder hands
over a full date of birth when a boolean would have done.

**Omitting the claim sets is not the milder choice, it is the harsher one.** §6.4.1: "If `claims` is
present, but `claim_sets` is absent, the Verifier requests all claims listed in `claims`", and "if the
Wallet cannot deliver all claims requested by the Verifier according to these rules, it MUST NOT return
the respective Credential". For the query above that means a holder lacking any one of the three
returns nothing at all, rather than disclosing more than you wanted.

**One set holding several ids is a combination, not a list of alternatives.** `["age18"], ["dob"]` is
two options in preference order. `["age18", "dob"]` is a single option demanding both, and a holder who
cannot produce both satisfies nothing. The two read alike and mean opposite things.

`Dcql.MdocByPath` is the same builder for mdoc. Every path there is the full `[namespace, element]` of
§7.2, and exactly two segments: §7.2.1 has the wallet "abort processing and return an error" for
anything else, so the builder refuses it rather than emitting a query no wallet may answer. A claim may
also carry `IntentToRetain`, which §B.2.4 scopes to mdoc, so setting it on an SD-JWT VC claim is
refused.

The builder refuses these at build time, because each fails the same silent way when it reaches a
wallet: the JSON serialises perfectly and the answer comes back with no claims, which reads as the
holder having nothing to offer. An id outside §6.3's alphanumeric, underscore and hyphen set; two
claims sharing an id; a set naming a claim that is absent; and a claim
that no set names, which §6.4.1 means would never be requested at all.

## 1. Live mode

```csharp
options.Mode = VerifierMode.Live;
```

In `Live` mode a started session stays pending until a wallet posts to the callback endpoint or the session lifetime (`options.SessionLifetime`, default 5 minutes) runs out. Everything else is identical to Mock mode, which is the point: Mock exercises the exact pipeline a live wallet hits.

Live mode also checks the configuration at startup and refuses to run with the demo request builder or the dev trust list still registered, so a demo configuration cannot quietly face real wallets. No demo, mock or test background services are hosted in Live mode.

The endpoints `MapTessioVerifier` exposes (default prefix `/verify`):

| Endpoint | Role |
| --- | --- |
| `GET /verify/start` | Creates a session and renders the request page with the `openid4vp://` authorization URI |
| `GET /verify/request/{id}` | Serves the signed request object (by-reference delivery, see below) |
| `GET /verify/{sessionId}` | Session status and result as JSON, for your own frontend. Carries no authorization request (see "What the session endpoints may say") |
| `GET /verify/{sessionId}/stream` | Server-Sent Events: `pending`, then `attempt_failed` when `failedAttempts` rises (with `CompleteOnlyOnValidResponse` on, and failures close together can share one), then `completed` or `expired` |
| `POST /verify/callback` | The wallet's `response_uri`. Returns 200 on completion, 400 for invalid or unknown responses, 409 when the session cannot take this response |

The callback endpoint enforces `state` correlation and completes each session exactly once, so replayed responses get a 409 (`session_not_pending`) and stray posts a 400. A response in a mode the request did not ask for also gets a 400 and does not end the session. That covers a plaintext form answering a `direct_post.jwt` request, and a `response` token that is not encrypted: OpenID4VP 1.0 §8.3 requires an unsigned, encrypted JWT.

**What a response that fails verification does is a setting.** By default it completes the session, and you read `Result.IsValid` false, so a holder whose wallet failed starts again with a new session. With `options.CompleteOnlyOnValidResponse = true` it gets a 400 instead, is recorded on the session as `LastFailure` and counted in `FailedAttempts`, and the session stays pending for another response until it expires. The status resource carries both, `lastFailure` narrowed exactly like `result`, and the stream sends `attempt_failed`. OpenID4VP 1.0 §8.6 requires the failing VP Token to be rejected and says nothing about the session, so both settings conform. The option is off by default because the frozen `VerificationSessionStatus` contract models a failed verification as completed, and turning it on changes that meaning for your deployment: a session then ends only as completed-and-valid or expired.

It also refuses a session whose stored request cannot be read, or whose query never said which credential type it asked for, with a 409 (`session_not_verifiable`). Verifying either one accepts a credential of any type, because the verifier skips the type comparison when it has nothing to compare rather than failing it.

The built-in store and request builders never produce such a session. Reaching it takes one of three things: a custom store that persisted less than the whole request, a custom `IPresentationRequestBuilder` that emits neither a request object nor the query parameters, or a hand-written DCQL entry that names no type. OpenID4VP 1.0 requires that name in both profiles, `vct_values` by §B.3.5 and `doctype_value` by §B.2.3, so `Dcql` always writes one and a query built through it always passes. See [self-driving-and-multi-tenant.md](self-driving-and-multi-tenant.md#3-persist-the-whole-request) for what has to survive.

## 2. Sign your requests

Live wallets require JAR-signed request objects (RFC 9101). Replace the default demo builder with `SignedPresentationRequestBuilder` and the key behind your wallet-facing certificate:

```csharp
using Tessio.Verifier.OpenId4Vp;

var cert = ...; // your WRPAC or access certificate, e.g. from a store or Key Vault
builder.Services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
    new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(cert.GetECDsaPrivateKey()!), SecurityAlgorithms.EcdsaSha256),
    }));
```

Any `SigningCredentials` works. For a key that never leaves Azure Key Vault or an HSM, point IdentityModel's signing at the remote key with a custom `CryptoProviderFactory`:

```csharp
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Tokens;

sealed class KeyVaultCryptoProviderFactory(CryptographyClient client) : CryptoProviderFactory
{
    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm) =>
        new KeyVaultSignatureProvider(client, key, algorithm);
}

sealed class KeyVaultSignatureProvider(CryptographyClient client, SecurityKey key, string algorithm)
    : SignatureProvider(key, algorithm)
{
    public override byte[] Sign(byte[] input) =>
        client.SignData(SignatureAlgorithm.ES256, input).Signature;

    public override bool Verify(byte[] input, byte[] signature) => throw new NotSupportedException();

    protected override void Dispose(bool disposing) { }
}
```

```csharp
var client = new CryptographyClient(new Uri("https://myvault.vault.azure.net/keys/verifier-jar"), credential);
var publicKey = new ECDsaSecurityKey(publicEcdsa); // public half, exported once from the vault

builder.Services.AddSingleton<IPresentationRequestBuilder>(new SignedPresentationRequestBuilder(
    new PresentationRequestBuilderOptions
    {
        SigningCredentials = new SigningCredentials(publicKey, SecurityAlgorithms.EcdsaSha256)
        {
            CryptoProviderFactory = new KeyVaultCryptoProviderFactory(client),
        },
    }));
```

Set `options.ClientId` to your registered identifier with its client-identifier prefix, for example `x509_san_dns:verifier.example.com`. The prefix tells the wallet how to validate your request against your certificate.

## 3. Deliver the request by reference

By default the signed request object is embedded in the `openid4vp://` URI. The start page renders that URI as a QR code for cross-device scanning, and a multi-kilobyte by-value JAR makes a dense code or exceeds QR capacity entirely (the page then shows the URI without a code). Set `RequestUriBase` and the wallet fetches the JAR over HTTPS instead, keeping the QR small:

```csharp
new PresentationRequestBuilderOptions
{
    SigningCredentials = ...,
    RequestUriBase = new Uri("https://verifier.example.com/verify/request"),
}
```

Point it at `{your host}{route prefix}/request`. `MapTessioVerifier` already serves stored request objects there with the required `application/oauth-authz-req+jwt` content type, and the start endpoint stores each session's JAR automatically. Request objects expire with their session.

## 4. Supply a real trust list

The default resolver trusts only the built-in demo and mock issuers, so real credentials will verify but report `Trusted = false` and fail. Live mode refuses to start with the default in place; register your own resolver before `AddTessioVerifier`.

How much you need to configure depends on how issuers prove their keys:

- **Issuer metadata** (`iss` HTTPS URI): the identifier is proven by control of the issuer's domain, so listing the identifier is enough.
- **X.509 (`x5c` header)**: the signing key comes from the presented certificate, so the identifier proves nothing on its own. Anyone can put a trusted issuer's name in a self-signed certificate. `StaticTrustListResolver` therefore requires the chain to anchor on a certificate you configure, and rejects x5c credentials when no anchors are set.

**The verifier fetches nothing a credential names for an issuer you do not trust.** On the metadata route, `SdJwtVcVerifier` asks your resolver about the `iss` value, with an empty chain, before it fetches the issuer's key. An untrusted issuer there fails with `issuer_untrusted` alone, because its key is never retrieved and nothing else can be checked. On the X.509 route the key arrives in the credential, so the signature is checked first and your resolver is then asked about the chain. On both routes the status list is fetched only for a trusted issuer, and `StaticTrustListResolver` builds a chain only from the presented certificates and your anchors, never downloading a certificate one of them points to. A Token Status List signer may send its own certificate alone, which HAIP 1.0 Final section 6.1 allows, while section 6.1.1 requires a credential to carry its chain. To accept such a signer, configure the certificate that issued it as an anchor alongside its root: the intermediate alone is not enough, because the chain still has to end on a root you configured. When a chain is refused because it is incomplete, the reason says where it stops and which issuer it names above that, which is the certificate to install. Every certificate on the anchor list is trusted for every purpose, so an intermediate added for status signers is also accepted as the signer of a credential, or as a pinned certificate in its own right.

This makes one demand of a resolver you write yourself. What it receives is chosen by whoever presented the credential: on the metadata route an identifier, before any signature has been checked, and on the X.509 route a chain whose certificates anyone can mint. Answer from your own configuration: a resolver that fetches, meters or records per request does so for input nobody has vouched for. If your resolver cannot decide, throw `HttpRequestException`, `IOException` or `TimeoutException` for a trust source it cannot reach, or `InvalidOperationException` when it is not in a state to answer, and let a timeout's `OperationCanceledException` propagate. The verifier fails the credential closed with `issuer_trust_unresolvable`, or `status_unresolvable` when the question was about a status list signer, and the resolver's message is kept in the error. Any other exception escapes as a defect.

```csharp
using Tessio.Verifier.Trust;

builder.Services.AddSingleton<ITrustListResolver>(new StaticTrustListResolver(
    ["https://pid-issuer.example.de"],
    source: "my-trust-list",
    trustAnchors: [rootCertificate]));   // CA roots or pinned issuer certificates
```

**Certificate validity is read on both paths.** Pinning a certificate says "this exact certificate",
not "this certificate forever": a pinned issuer certificate that has expired, or has not yet begun, is
rejected, and the reason names its window. An anchored chain is judged the same way, by the chain
builder. Expiry is what bounds how long a key stays trusted once nobody is looking after it, and a
pinned leaf is no exception to that.

Pass `clock:` when you verify at a chosen instant rather than at now, such as re-checking a stored
presentation or running a published conformance vector whose certificates have since expired. It
governs **both** paths, the pinned leaf and the chain build, so the answer cannot depend on which of
them a given configuration happens to take. Give it the **same** `TimeProvider` you give the verifier,
or the two halves judge one presentation at two different moments and disagree about exactly the
certificates whose window has closed.

```csharp
var clock = TimeProvider.System;   // or a fixed one, when replaying something frozen
new StaticTrustListResolver(issuers, trustAnchors: [rootCertificate], clock: clock);
```

For metadata-only issuers a plain identifier list works, loaded from a JSON document of the form `{"trusted_issuers": ["https://issuer.example", ...]}` on disk or at an HTTPS URL:

```csharp
builder.Services.AddSingleton<ITrustListResolver>(
    await TrustListLoader.LoadAsync("trusted-issuers.json"));
```

Or implement `ITrustListResolver` directly. It receives the credential's issuer identifier and its X.509 chain when one is present, and returns an `IssuerTrustStatus`. This is the seam for LOTL-derived national trust lists, your own registry or a managed trust service:

```csharp
public sealed class MyTrustResolver : ITrustListResolver
{
    public Task<IssuerTrustStatus> ResolveAsync(
        string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
    {
        // Look the issuer up in your trust source; inspect the chain if you anchor on certificates.
    }
}
```

`IssuerTrustStatus` carries more than the verdict, and what you populate is what a caller can record
afterwards. All of it is optional. The three below reach `VerificationResult.Issuer`; `Reason` does not,
and becomes a `VerificationResult.Errors[].Message` instead:

| Field | Set it to |
|---|---|
| `TrustListSource` | which list produced the verdict, **on a refusal as well as a pass**. A rejected presentation is the one a relying party has most reason to question, and "not trusted" without naming the list that was asked answers nothing. If your resolver consults several lists and none matched, null is the honest answer: no single list produced that refusal |
| `TrustAnchorSubject` | the anchor that vouched for the key, for a human reading a record. Null wherever no certificate was involved, which is the identifier route, and null on a refusal unless you know which configured anchor was matched and rejected |
| `TrustAnchorThumbprint` | that anchor's SHA-256 over its DER, uppercase hex, from `GetCertHashString(HashAlgorithmName.SHA256)`. This is the identity; a subject is not, because distinguished names are not unique |
| `Reason` | why, when the verdict is false |

**Two things to weigh before you populate them.** `source` is a label, not a location: the built-in
`TrustListLoader` passes the path or URL you hand it straight through, so the string can be a server
filesystem path, and a directory of anchor files can name the parties a deployment trusts. And these
fields describe the verdict rather than today's configuration, which is the point: reading a deployment's
current anchors back later answers a different question from the one an auditor asked.

### Debugging a chain that will not build

`StaticTrustListResolver` refuses on four paths, and they say different things:

| Refusal | The reason states |
|---|---|
| The identifier is not on the list | the identifier |
| An x5c chain arrived and the list holds no anchors | that this list does not accept a certificate-carried key |
| A pinned certificate matched and its validity window had closed | that certificate's subject and window |
| The chain would not build | the platform's chain status, the leaf's own issuer, and the leaf's authority key identifier |

Only the last one describes why a chain failed, and when its names look right and it still fails, two
environment variables widen it. Both are off by default, because a reason becomes a
`VerificationResult.Errors[].Message`:

| Variable | Set to `1` to add | Affects |
|---|---|---|
| `TESSIO_TRUST_DUMP_ANCHORS` | every configured anchor's subject and subject key identifier, or `none`. This is the usual answer: matching subjects with differing key identifiers is a certificate authority regenerated under its old name, which looks like it should have worked until both are on screen. It is also a list of the parties you anchor on, so turn it on, read it, turn it off | the no-anchors and chain-build refusals |
| `TESSIO_TRUST_DUMP_LEAF` | the presented leaf as base64 DER, for when the identifiers match too | the chain-build refusal |

Neither reaches the session endpoints, which replace every failure message (see below). They are for the
reason as your own code and logs receive it.

### What the session endpoints may say

The session status resource and its SSE stream are **anonymous**. They ask for a session id and nothing
else, and `GET {prefix}/start` hands one out, so treat whatever they return as public.

**Neither carries the authorization request.** A wallet's callback is matched to its session by
`state`, so `state` stays off anything keyed only by a session id. The authorization request URI leads to
`state` in both delivery modes, inside the request object by value or one anonymous fetch of
`request_uri` away by reference. The start page still shows it, as a QR code and a link, to the user
about to hand it to a wallet. If you build your own start page, drive the session yourself as
`self-driving-and-multi-tenant.md` describes, render the authorization URI server-side for that user,
and do not expose it on an endpoint keyed only by the session id.

Both send `Cache-Control: no-store`, because they carry a verdict and disclosed claims to whoever holds
the id, and a cache holding either would outlive the session. So do the start page and the request
object, the two responses that do carry `state`: a cache serving either to a second visitor would give
two people one session.

Both also narrow two things.

**Every failure message is replaced**, with `VerificationError.Code` left intact. The code is the stable
part a caller acts on; the message is prose written by whoever produced the failure, and it has been
observed to carry a locator. The built-in status list checks interpolate a URL and an inner exception
message, and an `ITrustListResolver` is free to name its list in a reason. Dropping all of them needs no
judgement about any one string. Your own surfaces read the stored result, where the messages are intact.

**`TrustListSource` becomes the literal `undisclosed`** unless the deployment has named the value as safe
to publish. The list is an allowlist, empty by default:

```csharp
services.AddTessioVerifier(options =>
{
    // A Commission-published trusted list URL is already public, so naming it helps an integrator.
    options.PublicTrustListSources.Add("https://ec.europa.eu/.../age-verification-list.xml");
});
```

An allowlist rather than a rule that hides paths, because a rule has to judge whether a string looks
sensitive and fails open on the first shape nobody anticipated. This fails closed: unlisted means
undisclosed. Nothing useful is lost, since "a list was consulted and your issuer was not on it" is the
part a caller acts on, and the token still says that.

`undisclosed` and `null` are different answers. `undisclosed` means a list produced this verdict and is
not named here. `null` means no attribution is available, which covers both "no list was consulted" and
"the resolver in use reports no source", and those two cannot be told apart.

The anchor subject and thumbprint are **not** narrowed. The caller's own credential is what produced them,
so they name the one anchor that caller has just proved it chains to, rather than the set you hold. Note
what that does and does not cover: if you pin individual document signer certificates as anchors rather
than a published root, an anonymous caller learns the digest of the one you pinned for that issuer.

The rule generalises, and it is worth applying to any diagnostic field added after this one: **one field,
two boundaries.** The anonymous surface gets a fixed token, and a surface you authorise and scope yourself
gets the whole string. Your own endpoints read `VerificationResult` straight from the session store, which
the narrowing never touches, so the full value is there when the caller is known.

**One more channel to know about.** `IssuerInfo` is a record, so its generated `ToString()` prints every
property, `TrustListSource` included, and `VerificationResult.ToString()` nests it. Nothing in this library
stringifies a result, but a consumer that logs one, interpolates it into a message, or lets it reach an
exception an error monitor captures sends the locator wherever those go. The narrowing is a boundary on
the JSON these endpoints serve, not on the object.

## 5. Share sessions across instances

The default `InMemorySessionStore` is process-local. Behind a load balancer the wallet's callback can land on a different instance than the one that started the session, so the store must be shared. Implement `IStateCorrelatingSessionStore` over Redis, SQL or any shared storage:

```csharp
public sealed class RedisSessionStore : IStateCorrelatingSessionStore
{
    public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default);
    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default);
    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default);
    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default);
}
```

```csharp
builder.Services.AddSingleton<ISessionStore, RedisSessionStore>();
```

`FindByStateAsync` is the extra member beyond the base `ISessionStore`: a wallet response carries only the OpenID4VP `state` value, so the callback path needs a state index next to the sessions. Registering a store without it fails fast with an explanatory exception on the first callback.

With `CompleteOnlyOnValidResponse` on, the store must also implement `IAttemptRecordingSessionStore`, whose `RecordFailedAttemptAsync` sets `LastFailure`, increments `FailedAttempts` and leaves the session pending. It must do nothing once the session has left `Pending`, so a failure that loses a race with a valid response cannot overwrite it. A store without it fails fast the same way, when the callback is first built.

If you drive creation and completion from your own API (bypassing `/start` and `/callback`) or host many tenants in one process, see [self-driving-and-multi-tenant.md](self-driving-and-multi-tenant.md) for the `IWalletResponseVerifier` seam, a durable Postgres store and the request-object round-trip.

Two behaviors to know:

- `CreateAsync` builds the presentation request (inject `IPresentationRequestBuilder`) and must index the request's `state`. Complete each session at most once and treat later completions as no-ops or conflicts.
- The SSE stream endpoint gets push notifications from the in-memory store. With a custom store it polls `GetAsync` every 500 ms until the session leaves `Pending` or its `FailedAttempts` changes, which works unchanged with any store.

## 6. Response encryption across instances

With `ResponseMode.DirectPostJwt` (the default and the HAIP baseline) wallets encrypt their responses to a key published in your request's `client_metadata.jwks`.

**The key is ephemeral per authorization request, not per process.** OpenID4VP 1.0 §8.3 and HAIP 1.0 §5 require this, and the conformance suite fails a verifier that reuses one. The reasons are real: a single long-lived key means its compromise retrospectively exposes every response ever encrypted against it, and a stable advertised public key is a correlation handle tying separate presentations to one verifier. `ResponseEncryptionKeyStore` generates a fresh P-256 key at `/verify/start`, holds it in memory, and the callback finds it again by the `kid` (RFC 7638 thumbprint) the wallet echoes in the JWE header. **The private half never touches disk.**

**Resolving by `kid` is spec-mandated, so decryption requires it with no fallback.** OpenID4VP 1.0 §5 requires that every JWK in `client_metadata.jwks` carry a `kid`, and §8.3 then requires that "if the selected public key contains a `kid` parameter, the JWE MUST include the same value in the `kid` JWE Header Parameter" of the encrypted response. The advertised key always has a `kid`, so a conformant wallet always echoes it. A response that carries none, or names a `kid` the store no longer holds, is rejected rather than decrypted against a guessed key: for `direct_post.jwt` the `state` that correlates the session lives inside the ciphertext, so the `kid` is the only handle available before decryption, and quietly trying "the only key we have" would reintroduce the shared-key ambiguity this design exists to remove. Failing loud surfaces a non-conformant wallet instead of masking it.

That default is complete for a **single process**. Across instances it breaks the same way sessions do: instance A generates the key and holds it in its own memory, so instance B cannot decrypt a response routed to it.

**Recommended when you scale out: derive the key, store no key material.** Do not persist private keys, not even encrypted. Keep one master secret in a KMS or HSM, ideally non-exportable, and derive each request's private scalar from it:

```
d    = HKDF(master, salt)      // salt: a fresh random value per request
kid  = base64url SHA-256 thumbprint of the public JWK
```

Store only the non-secret `salt`, keyed by `kid`, in the shared store you already run for sessions (§5). At the callback, any instance reads the `salt` for the response's `kid`, re-derives `d` from the master secret it reaches via the KMS, and decrypts. The database holds a random salt and nothing secret; the only long-lived secret is the master, which can live in hardware and never be exported.

Why not the alternatives:
- **Persisting the private key**, even as KMS-encrypted ciphertext in Postgres, puts key material in your database. Derivation avoids that entirely.
- **Sticky sessions** (route the callback to the instance that issued the request) store nothing, but couple you to load-balancer affinity and lose the key if that instance restarts mid-flow. A reasonable stopgap, not the target.

This derivation path is **not yet wired into the library**, deliberately: no consumer has needed it yet, and adding the seam before one does would be speculative (see the extract-when-needed rule). When you scale out, the change is a pluggable key source on `ResponseEncryptionKeyStore` (create-from-salt, resolve-by-kid) backed by your KMS. On a single instance the in-memory default is correct and needs no configuration.

`ResponseMode.DirectPost` (cleartext form posts) is also supported, but encrypted responses are the profile default so stay on `DirectPostJwt` unless you have a reason not to.

## Requesting mdocs instead of SD-JWT VC

The same pipeline verifies ISO mobile documents (the mDL and the mdoc flavour of the PID). One option switches the credential format:

```csharp
builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Live;
    options.CredentialFormat = "mso_mdoc";
    options.ExpectedDocType = "org.iso.18013.5.1.mDL";   // or eu.europa.ec.eudi.pid.1
    options.MdocNamespace = "org.iso.18013.5.1";
    options.RequestedClaims = ["age_over_18"];
});
```

The DCQL query then uses `doctype_value` and `[namespace, element]` claim paths, and responses are verified by `MdocVerifier`: issuer signature via the `x5chain` Document Signer certificate, per-item digests against the Mobile Security Object, validity window and the device signature over the OpenID4VP session transcript (which binds your client_id, nonce, response_uri and response-encryption key).

Two things differ from the SD-JWT path:

- **Trust anchors are mandatory.** mdoc trust is X.509 only (IACA roots), so your `ITrustListResolver` must anchor chains; an identifier list alone rejects everything. Pass the IACA certificates as `trustAnchors` and list the Document Signer subjects as issuers.
- **Stay on `direct_post.jwt`.** The high-assurance profile requires encrypted responses for mdocs, and the encryption key's thumbprint is part of what the wallet's device signature covers.

Mock mode works the same way: with `CredentialFormat = "mso_mdoc"` the built-in wallet issues real device-signed DeviceResponses, so you can exercise the whole mdoc flow offline. The mdoc pipeline is verified against external artifacts at every layer: the ISO 18013-5 Annex D worked example (parsing, digests and issuer signature agree with the spec's own bytes), the OpenID4VP Annex B.2.6 transcript vectors (byte-identical to the EUDI reference wallet's own test expectations) and a cross-implementation round trip in which an independent mdoc stack (OpenWallet Foundation wallet-framework-dotnet) built and signed the device authentication that this verifier accepts.

## Adjusting verification policy

`SdJwtVcVerifier` defaults are strict: key binding required, credential status (Token Status List) checked and failing closed, 5 minutes of clock skew. To change them, register the verifier yourself:

```csharp
using Tessio.Verifier.Core;

builder.Services.AddSingleton<ICredentialVerifier>(sp => new SdJwtVcVerifier(
    sp.GetRequiredService<ITrustListResolver>(),
    new SdJwtVcVerifierOptions
    {
        ClockSkew = TimeSpan.FromMinutes(2),
        // RequireKeyBinding = false,   // only for credentials without cnf
        // CheckStatus = false,         // only if you accept revoked-credential risk
    },
    clock: sp.GetRequiredService<TimeProvider>()));
```

Verification results carry stable error codes (`nonce_mismatch`, `untrusted_issuer`, `credential_revoked` and so on) in `VerificationResult.Errors`, so your application logic and your logs can branch on codes rather than messages.

**What a credential can make the verifier fetch, and the limits on it.** An SD-JWT VC can make the verifier fetch its issuer's JWT VC Issuer Metadata and the `jwks_uri` that metadata names, its status list, and the status list signer's metadata and key set. Each of those must be HTTPS and is read only up to a size limit, and each has its own deadline, so a credential that causes several waits on them in sequence. A status list is also limited in size once decompressed. The values, and the reason for each, are the constants at the top of `src/Tessio.Verifier.Core/OutboundFetch.cs`. The verifier's default client also refuses a host that resolves outside the public internet, does not follow redirects and ignores the process proxy, because through a proxy the address check would see only the proxy. The check runs inside the connection, which then connects to exactly the addresses checked, so a DNS answer that changes between the check and the connection cannot slip past. An issuer whose metadata redirects therefore fails with `issuer_key_unresolvable`, and a status list that redirects fails with `status_unresolvable`. If you pass your own `HttpClient`, the deadline and the size limits still apply, but the address check, the redirect refusal and the proxy refusal do not, so give it a handler that enforces them. SD-JWT VC draft -13 section 10.1 requires the address check, a time bound and a size bound for the issuer metadata endpoint. Applying them to every fetch a credential causes, and refusing redirects, are this library's choices.

`VerificationResult.CredentialType` reports what was **presented**: the `vct` for SD-JWT VC, the `docType`
for mdoc. You already know what you asked for, so this only earns its place once a request names several
types, as [above](#when-those-types-put-the-same-fact-in-different-places): then it is the only way to
learn which one the holder actually produced, and it is populated on the failing path too, where it
answers "a mismatch against what?". It is null when verification failed before the type could be read,
which means "not established" rather than "the credential declared none".

## Binding transactions into presentations

For flows where the credential authorizes a specific act (a payment, a contract signature), OpenID4VP transaction data binds the holder's signature to that act. Supply the transaction objects and the rest is automatic: they ride base64url-encoded in the signed request, the wallet hashes each one into its Key Binding JWT and the verifier rejects presentations whose hashes are missing or wrong.

```csharp
options.TransactionData = ["""{"type":"payment_confirmation","amount":"120.00 EUR"}"""];
```

`credential_ids` defaults to the query's credential id. Failures surface as `transaction_data_missing`, `transaction_data_hash_mismatch` or `transaction_data_alg_unsupported`. SD-JWT VC flows only; the mechanism requires key binding.

## Observability

The pipeline logs through `Microsoft.Extensions.Logging`, so whatever your host configures (console, Application Insights, OpenTelemetry) picks it up with no extra wiring. Session creation logs under `Tessio.Verifier.Sessions`; callback handling logs under the `WalletCallbackProcessor` category. Every rejected wallet response logs a warning with the cause (parse failure, missing or unknown state, replay) and every completion logs the verification outcome with its error codes. Disclosed claims and credential contents are never logged.

## What the library does not cover

Verifying real EUDI wallets in production also requires registering as a relying party in your member state, plus maintained EU trust lists, and for a profile that signs its requests a wallet-relying party access certificate (WRPAC) from a certificate authority your member state has authorised. See [docs/production.md](https://github.com/tripledownab/tessio-verifier/blob/main/docs/production.md) for that landscape. The library covers the protocol and the credential verification; the registration and trust layer is yours or a provider's.

## Checklist

- [ ] `VerifierMode.Live`
- [ ] `SignedPresentationRequestBuilder` with your certificate's key (HSM or Key Vault via `CryptoProviderFactory`)
- [ ] `ClientId` set to your registered identifier with its prefix
- [ ] `RequestUriBase` set so QR codes stay small
- [ ] Real `ITrustListResolver` registered, with trust anchors for issuers that use x5c
- [ ] `PublicTrustListSources` names every trust list identifier you are content to publish, and nothing else
- [ ] Multi-instance: `IStateCorrelatingSessionStore` over shared storage
- [ ] Multi-instance: `ResponseEncryptionKeyProvider` built from one persisted key
- [ ] Callback endpoint reachable over HTTPS from the public internet
- [ ] Verified end to end in Mock mode first, then against a reference wallet
