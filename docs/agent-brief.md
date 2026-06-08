# Agent Brief & Source Document — Open-Source .NET EUDI Wallet Verifier

**Working name:** Tessio.Verifier
**Owner:** Triple Down AB
**Date:** June 2026
**Status:** v0.1 build, multi-agent parallel execution

---

## 0. How to use this document

This is the single source of truth for agents building the v0.1 open-source verifier. Read it fully before writing code. It contains: the master prompt to seed each agent, project context, authoritative source links, the technical spec, a parallelizable workstream split with locked contracts, and the definition of done.

**Critical coordination rule:** Phase 0 (locking the shared contracts — interfaces and DTOs) must be completed and committed *before* any agent starts implementation work. Agents work against frozen contracts so their packages compose without collision. Do not change a published contract without flagging it.

---

## 1. Master prompt (seed every agent with this)

> You are building part of an open-source, production-grade **.NET / ASP.NET Core library that lets a Relying Party (Verifier) verify credentials presented by an EU Digital Identity (EUDI) Wallet**, over the **OpenID4VP 1.0** protocol, for **SD-JWT VC** credentials. This is the relying-party (verifier) side only — never the wallet/holder side.
>
> The goal is the cleanest, most idiomatic .NET developer experience in this space: a developer should `dotnet add package`, wire up an ASP.NET Core endpoint, and run a full verification flow in **demo mode** within minutes — before any real wallet exists. The protocol/verification code is the open-source wedge; the managed trust infrastructure (WRPAC, 27-state trust lists, hosting) is a separate commercial layer and is **out of scope** here, though we expose clean seams for it.
>
> Constraints: target **.NET 8 (LTS)**, multitarget `net8.0;net9.0` where trivial. **Never roll your own cryptography** — use platform primitives (`System.Security.Cryptography`, `System.Formats.Cbor`, Microsoft.IdentityModel JWT libraries) and well-known packages. License is **Apache-2.0**. Everything must be unit-tested, with verification logic tested against published spec test vectors. Follow the spec versions and the contracts in the brief exactly. When a spec detail is ambiguous, prefer the **EUDI ARF** and the **HAIP (High Assurance Interoperability Profile)** interpretation, and leave a `// SPEC:` comment citing the source.
>
> You will be assigned one workstream (A–E). Only touch your workstream's project(s). Consume other workstreams through the frozen contracts in Section 6. Do not edit published contracts.

---

## 2. Project context & strategy (why, so agents make aligned tradeoffs)

- The EUDI Wallet is mandated by **Regulation (EU) 2024/1183 (eIDAS 2.0)**. Every EU member state must make at least one wallet available by **6 December 2026**; regulated relying parties must **accept** wallets by **6 December 2027**.
- The Commission published strong **holder/wallet** reference code but the **relying-party (verifier)** side is thin. The notable open-source verifier efforts are **walt.id (Kotlin/JVM)**, **SpruceID (Rust)**, and **eIDAS Pro / OpenEUDI (TypeScript)**. **There is no strong .NET/C# relying-party verifier.** Nordic and EU regulated firms run on Microsoft/.NET — that is the gap and the wedge.
- Our differentiation is **ecosystem fit (native .NET/ASP.NET/Azure)** and **developer experience**, not novel protocol work. The protocol is standardized; we win on being the obvious drop-in for a .NET shop.
- Therefore: **idiomatic .NET, excellent docs, demo mode, and conformance evidence matter more than feature breadth.** Ship a narrow, correct, delightful core fast.

---

## 3. Authoritative sources & links (annotated)

**Protocols / specifications (normative — implement against these):**
- **OpenID4VP 1.0** (final) — the verifier↔wallet presentation protocol: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- **SD-JWT VC** (IETF, latest draft — currently draft-16, 2026): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc
- **SD-JWT (base format)** — Selective Disclosure for JWTs, the layer SD-JWT VC builds on: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt
- **OAuth JAR (RFC 9101)** — JWT-Secured Authorization Requests: https://www.rfc-editor.org/rfc/rfc9101
- **ISO/IEC 18013-5 / 18013-7** — mdoc / mDL (proximity & remote). *v0.2 only, deferred.* (ISO, paywalled — reference by standard number.)

**EUDI framework (authoritative interpretation — defer to these when specs are ambiguous):**
- **EUDI Architecture & Reference Framework (ARF)** repo: https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- **EUDI Wallet GitHub org** (browse for reference libraries, incl. JVM SD-JWT and OpenID4VP libs to study): https://github.com/eu-digital-identity-wallet
- **Reference Verifier endpoint (Kotlin)** — closest analog to what we're building; study its flow: https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint
- **Reference OpenID4VP library (Kotlin)** — protocol handling reference: https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt
- **Regulation (EU) 2024/1183 (eIDAS 2.0)**: https://eur-lex.europa.eu/eli/reg/2024/1183/oj

**Trust infrastructure (read for context; mostly commercial-layer, build only the seam):**
- **ETSI TS 119 475** — Relying Party attributes / WRPAC profile (reference by standard number at the ETSI portal).
- WRPAC = Wallet Relying Party Access Certificate; RPRC = Relying Party Registration Certificate. Trust chain hierarchy: EU List of Trusted Lists (LOTL) → national trusted list → trust service provider → certificate.

**Prior art to study (do not copy; understand the shape):**
- walt.id docs (Kotlin): https://docs.walt.id
- eIDAS Pro / OpenEUDI (TypeScript open core + managed service — our closest competitor, different language and lane): https://eidas-pro.com and their stated repo https://github.com/openeudi *(verify it has published)*

---

## 4. Spec gotchas agents MUST respect (these trip people up)

1. **`dc+sd-jwt`, not `vc+sd-jwt`.** The SD-JWT VC `typ` header and media type changed from `vc+sd-jwt` to **`dc+sd-jwt`** (media type `application/dc+sd-jwt`) in late 2024 to avoid a W3C conflict. Older tutorials/examples use the old value — do not. Support reading legacy `vc+sd-jwt` only behind a compatibility flag.
2. **Use DCQL, not Presentation Exchange.** Recent OpenID4VP replaced Presentation Exchange (PEx) with **DCQL** (Digital Credentials Query Language) for the query structure. Implement DCQL.
3. **Issuer key resolution = two mechanisms.** Per SD-JWT VC: (a) **JWT VC Issuer Metadata** (web resolution when `iss` is an HTTPS URI) and (b) **X.509 certificate chain** (`x5c`/`x5t` in header). Implement both.
4. **Key Binding JWT (KB-JWT)** verifies holder binding — validate it (audience, nonce, signature) when present/required.
5. **Response modes.** Support `direct_post` and `direct_post.jwt` (the latter is an encrypted JWE response — implement JWE decryption). Cross-device flow (QR) is primary.
6. **Replay/freshness.** Enforce `nonce` and `state`; reject reused/expired.
7. **Align to HAIP** (High Assurance Interoperability Profile) where it constrains choices — it's the EUDI-relevant profile.

---

## 5. Technical scope

### In scope (v0.1)
- OpenID4VP 1.0 **verifier role**: build presentation request (DCQL), sign request object (JAR / RFC 9101), `request_uri` by-value and by-reference, QR/deep-link delivery, receive & parse response (`direct_post`, `direct_post.jwt` w/ JWE), extract `vp_token`.
- **SD-JWT VC verification**: parse, verify issuer signature (both key-resolution mechanisms), reconstruct & hash-verify disclosures, verify KB-JWT, nonce/replay protection, selective-disclosure claim extraction.
- **Session management**: create/track/complete; pluggable session store (in-memory default); results via SSE and callback.
- **Demo / Mock / Test modes**: DEMO auto-completes for showcases; MOCK returns canned wallet responses; TEST runs full protocol against fixtures. **Mandatory and high priority** — no real wallets exist yet, so this is how anyone evaluates us.
- **ASP.NET Core integration**: DI extensions, minimal-API endpoints, sample relying-party app.
- **Pluggable trust seam**: `ITrustListResolver` + a basic file/URL implementation (the commercial layer replaces this).

### Out of scope (do NOT build)
- WRPAC procurement, RP registration, QTSP integration (commercial layer).
- Full 27-state LOTL aggregation / auto-refresh (commercial layer).
- mdoc / ISO 18013-5 proximity (BLE/NFC) — and mdoc remote is **v0.2**, not v0.1.
- Hosted infra, dashboards, billing, compliance-grade audit pipeline, SLA.
- Any wallet/holder-side or issuer-side functionality.

### Tech choices
- .NET 8 LTS (multitarget net9.0 where trivial). Apache-2.0 license.
- JOSE/JWT: Microsoft.IdentityModel.JsonWebTokens; ECDSA P-256 / ES256 expected. CBOR: `System.Formats.Cbor` (for v0.2 mdoc). COSE: `System.Security.Cryptography.Cose` (v0.2). X.509: `System.Security.Cryptography.X509Certificates`. BouncyCastle only if a primitive is genuinely missing.
- **No custom crypto.** SD-JWT processing is built on top of vetted JOSE primitives (there is no mature .NET SD-JWT lib — that's the gap; implement it cleanly and test hard).

### Package layout (NuGet)
- `Tessio.Verifier.Core` — credential verification (SD-JWT VC, disclosures, KB-JWT, issuer key resolution). No web dependencies.
- `Tessio.Verifier.OpenId4Vp` — protocol layer (request build, JAR, response parse/JWE). Depends on Core.
- `Tessio.Verifier.AspNetCore` — DI, endpoints, session, demo/mock/test modes, SSE. Depends on OpenId4Vp.
- `Tessio.Verifier.Trust` — `ITrustListResolver` + basic impl. Referenced by Core (issuer trust) and OpenId4Vp.
- `samples/Tessio.Sample.RelyingParty` — runnable demo web app (not packaged).

---

## 6. Parallel workstreams & FROZEN CONTRACTS

> **Phase 0 (do first, single small team/agent):** create the solution, the five projects, CI (build + test + pack), and the **contract types below as compiled interfaces/DTOs**. Commit and tag `contracts-v0`. Only then fan out A–E.

**Workstream A — Verification core** (`Tessio.Verifier.Core`)
Implements SD-JWT VC verification. Produces `VerificationResult`. Consumes `ITrustListResolver`. No web, no protocol. Heavy test-vector coverage.

**Workstream B — OpenID4VP protocol** (`Tessio.Verifier.OpenId4Vp`)
Builds requests (DCQL + JAR), handles `request_uri`, parses responses (`direct_post`/`direct_post.jwt`+JWE), extracts `vp_token`, hands credentials to A via `ICredentialVerifier`.

**Workstream C — ASP.NET Core + sessions + modes** (`Tessio.Verifier.AspNetCore`)
DI extensions, minimal-API endpoints (request init, wallet callback, result stream), `ISessionStore` (in-memory default), SSE, and `DEMO`/`MOCK`/`TEST` mode providers.

**Workstream D — Trust seam** (`Tessio.Verifier.Trust`)
`ITrustListResolver` + a file/URL implementation; LOTL model stubbed. This is the commercial seam — keep the interface clean and minimal.

**Workstream E — Sample app, docs, conformance** (`samples/` + `/docs` + test harness)
Runnable RP sample (starts in DEMO mode), README 5-minute quickstart, and a conformance harness aimed at the EUDI/OpenWallet test suites. Can start immediately against mocks.

### Frozen contracts (locked in Phase 0)

All DTOs use init-only `required` properties so the shapes are **forward-compatible**: new optional fields can be added to a later `contracts-v0.x` tag without breaking existing callers' constructors.

```csharp
// Tessio.Verifier.Core (contracts)
public interface ICredentialVerifier {
    Task<VerificationResult> VerifyAsync(PresentedCredential credential,
                                         VerificationContext context,
                                         CancellationToken ct = default);
}

public sealed record PresentedCredential {
    public required string Format { get; init; }   // "dc+sd-jwt" (SPEC: not vc+sd-jwt)
    public required string RawValue { get; init; }
}

public sealed record VerificationContext {
    public required string Nonce { get; init; }
    public required string Audience { get; init; }
    public string? ExpectedVct { get; init; }
}

public sealed record VerificationResult {
    public required bool IsValid { get; init; }
    public required IReadOnlyDictionary<string, object> DisclosedClaims { get; init; }
    public required IssuerInfo Issuer { get; init; }
    public required IReadOnlyList<VerificationError> Errors { get; init; }
}

public sealed record IssuerInfo {
    public required string Identifier { get; init; }
    public required bool Trusted { get; init; }
    public required string KeyResolutionMethod { get; init; }   // "jwt-vc-issuer-metadata" | "x5c"
}

public sealed record VerificationError {
    public required string Code { get; init; }
    public required string Message { get; init; }
}

// Tessio.Verifier.Trust (contracts)
public interface ITrustListResolver {
    Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c,
                                         CancellationToken ct = default);
}
public sealed record IssuerTrustStatus {
    public required bool Trusted { get; init; }
    public string? TrustListSource { get; init; }
    public string? Reason { get; init; }
}

// Tessio.Verifier.OpenId4Vp (contracts)
public enum ResponseMode { DirectPost = 0, DirectPostJwt = 1 }   // HAIP default: DirectPostJwt

public sealed record PresentationRequestOptions {
    public required string ClientId { get; init; }
    public required string Nonce { get; init; }
    public required string DcqlQueryJson { get; init; }          // SPEC: DCQL, not PEx
    public required Uri ResponseUri { get; init; }
    public ResponseMode ResponseMode { get; init; } = ResponseMode.DirectPostJwt;
    public string? State { get; init; }
    public TimeSpan? RequestLifetime { get; init; }
    public string? ClientMetadataJson { get; init; }             // HAIP verifier display metadata
    public string? TransactionDataJson { get; init; }            // HAIP transaction-binding
}

public abstract record PresentationRequest {
    public required string ClientId { get; init; }
    public required string Nonce { get; init; }
    public string? State { get; init; }
    public required Uri AuthorizationRequestUri { get; init; }
    public required string SignedRequestObject { get; init; }    // JAR (RFC 9101) JWT
    public required DateTimeOffset ExpiresAt { get; init; }

    public sealed record ByValue : PresentationRequest;
    public sealed record ByReference : PresentationRequest {
        public required Uri RequestUri { get; init; }            // wallet fetches JAR here
    }
}

// Host-agnostic wallet response (decouples protocol parser from ASP.NET).
public sealed record WalletResponseData {
    public required string ContentType { get; init; }
    public required IReadOnlyDictionary<string, IReadOnlyList<string>> Form { get; init; }  // direct_post
    public required ReadOnlyMemory<byte> Body { get; init; }                                // direct_post.jwt
}

public interface IPresentationRequestBuilder {
    Task<PresentationRequest> BuildAsync(PresentationRequestOptions options, CancellationToken ct = default);
}
public interface IPresentationResponseParser {
    Task<IReadOnlyList<PresentedCredential>> ParseAsync(WalletResponseData response, CancellationToken ct = default);
}

// Tessio.Verifier.AspNetCore (contracts)
public enum VerificationSessionStatus { Pending = 0, Completed = 1, Expired = 2 }
// Completed covers both pass and fail — inspect VerificationResult.IsValid.

public sealed record VerificationSession {
    public required string SessionId { get; init; }
    public required PresentationRequest Request { get; init; }
    public required VerificationSessionStatus Status { get; init; }
    public VerificationResult? Result { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
}

public interface ISessionStore {
    Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default);
    Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default);
    Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default);
}
```

**Deviations from the original brief** (intentional, blessed during Phase 0):
- `HttpRequestData` → `WalletResponseData`. The original name collided with `Microsoft.Azure.Functions.Worker.Http.HttpRequestData` and misrepresented the type as a generic HTTP abstraction.
- `PresentationRequest` is a sealed hierarchy (`ByValue` / `ByReference`) instead of a single record — by-value vs by-reference delivery is type-discriminated rather than convention-encoded.
- All DTOs use init-only `required` properties instead of positional records, so optional fields can be added in later contract versions without breaking callers.
- `ResponseMode` is an enum (with explicit numeric values), not a string. `VerificationSessionStatus` drops `Failed`; verification-level failure is carried by `VerificationResult.IsValid` inside a `Completed` session.
- `IPresentationRequestBuilder.Build` → `BuildAsync` (returns `Task<PresentationRequest>` and accepts `CancellationToken`). Reason: real-world JAR signing uses an HSM, Azure Key Vault, AWS KMS, or another remote key store — all asynchronous. Synchronous in-memory signers can return `Task.FromResult`.

---

## 7. Coding standards & definition of done

- Nullable enabled, warnings-as-errors, analyzers on. Public API documented with XML comments.
- **Tests:** unit tests per package; SD-JWT VC verification tested against **published spec test vectors** (from the IETF draft and EUDI reference suites). Negative tests for tampered signatures, expired/missing nonce, bad disclosures, untrusted issuer.
- A green `DEMO`-mode end-to-end run through the sample app is part of "done."
- README quickstart must take a fresh dev from zero to a verified DEMO result in ≤5 minutes.
- `// SPEC:` comments citing the relevant spec section for every non-obvious protocol/crypto decision.
- Conventional commits; CI must build, test, and `dotnet pack` all packages.

**v0.1 is "done" when:** a developer can install the packages, run the sample RP in DEMO mode, see a verified set of disclosed claims, and swap to MOCK/TEST mode against fixtures — with SD-JWT VC verification passing the spec test vectors and the trust seam pluggable.

---

## 8. Glossary
- **RP / Relying Party / Verifier** — the business verifying a credential (our customer).
- **OpenID4VP** — protocol the wallet uses to present credentials to the RP.
- **SD-JWT VC** — selectively-disclosable JWT credential format (remote/online flows).
- **mdoc / mDL** — ISO 18013-5 CBOR credential (proximity; v0.2).
- **DCQL** — query language for requesting credentials (replaced Presentation Exchange).
- **JAR** — JWT-Secured Authorization Request (RFC 9101).
- **KB-JWT** — Key Binding JWT (proves holder binding).
- **HAIP** — High Assurance Interoperability Profile (EUDI-relevant constraints).
- **WRPAC / RPRC** — Wallet Relying Party Access / Registration Certificates (commercial layer).
- **LOTL** — EU List of Trusted Lists (trust hierarchy root).
