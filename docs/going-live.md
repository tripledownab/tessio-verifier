# Going live

How to take a Tessio.Verifier app from the built-in Demo, Mock and Test modes to real wallets.

The built-in modes exist so you can build and test without a wallet. Going live means five things change: the mode, the request signature, the trust list, the session store and the response encryption key. Each is a service you register before `AddTessioVerifier`, which uses `TryAdd` for everything and therefore keeps whatever you registered first.

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
| `GET /verify/{sessionId}` | Session status as JSON, for your own frontend |
| `GET /verify/{sessionId}/stream` | Server-Sent Events: `pending`, then `completed` or `expired` |
| `POST /verify/callback` | The wallet's `response_uri`. Returns 200 on completion, 400 for invalid or unknown responses, 409 for replays |

The callback endpoint enforces `state` correlation and completes each session exactly once, so replayed responses get a 409 and stray posts a 400.

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

By default the signed request object is embedded in the `openid4vp://` URI. That URI becomes a QR code in cross-device flows, and a multi-kilobyte JAR makes a dense, slow-to-scan code. Set `RequestUriBase` and the wallet fetches the JAR over HTTPS instead:

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

```csharp
using Tessio.Verifier.Trust;

builder.Services.AddSingleton<ITrustListResolver>(new StaticTrustListResolver(
    ["https://pid-issuer.example.de"],
    source: "my-trust-list",
    trustAnchors: [rootCertificate]));   // CA roots or pinned issuer certificates
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

Two behaviors to know:

- `CreateAsync` builds the presentation request (inject `IPresentationRequestBuilder`) and must index the request's `state`. Complete each session at most once and treat later completions as no-ops or conflicts.
- The SSE stream endpoint gets push notifications from the in-memory store. With a custom store it polls `GetAsync` every 500 ms until the session leaves `Pending`, which works unchanged with any store.

## 6. Share the response encryption key

With `ResponseMode.DirectPostJwt` (the default and the HAIP baseline) wallets encrypt their responses to a key published in your request's `client_metadata.jwks`. The default key is ephemeral and per-process, which breaks under load balancing the same way sessions do: instance A advertises a key that instance B cannot use to decrypt.

Load one persisted P-256 key everywhere:

```csharp
using System.Security.Cryptography;

var key = ECDsa.Create();
key.ImportPkcs8PrivateKey(pkcs8Bytes, out _); // from Key Vault, a secret store or a mounted file

builder.Services.AddSingleton(new ResponseEncryptionKeyProvider(key));
```

Every instance holding the same key advertises the same JWK with the same RFC 7638 thumbprint `kid`, and any instance can decrypt any wallet's response. Note this key is used for ECDH-ES key agreement, so unlike the JAR signing key it must be present in the process; keep it in a secret store, not in the repo.

`ResponseMode.DirectPost` (cleartext form posts) is also supported, but encrypted responses are the profile default so stay on `DirectPostJwt` unless you have a reason not to.

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

## What the library does not cover

Verifying real EUDI wallets in production also requires registering as a relying party in your member state and holding a Wallet Relying Party Access Certificate (WRPAC) from a Qualified Trust Service Provider, plus maintained EU trust lists. See [docs/production.md](https://github.com/tripledownab/tessio-verifier/blob/main/docs/production.md) for that landscape. The library covers the protocol and the credential verification; the registration and trust layer is yours or a provider's.

## Checklist

- [ ] `VerifierMode.Live`
- [ ] `SignedPresentationRequestBuilder` with your certificate's key (HSM or Key Vault via `CryptoProviderFactory`)
- [ ] `ClientId` set to your registered identifier with its prefix
- [ ] `RequestUriBase` set so QR codes stay small
- [ ] Real `ITrustListResolver` registered, with trust anchors for issuers that use x5c
- [ ] Multi-instance: `IStateCorrelatingSessionStore` over shared storage
- [ ] Multi-instance: `ResponseEncryptionKeyProvider` built from one persisted key
- [ ] Callback endpoint reachable over HTTPS from the public internet
- [ ] Verified end to end in Mock mode first, then against a reference wallet
