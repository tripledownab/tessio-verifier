# CLAUDE.md — Tessio.Verifier

Open-source **.NET / ASP.NET Core verifier for the EU Digital Identity (EUDI) Wallet**. Relying-party (verifier) side only — never wallet or issuer. Protocol: **OpenID4VP 1.0**. Credential: **SD-JWT VC**. Full spec: `docs/agent-brief.md` — read it before writing code.

## Your job
Build the cleanest, most idiomatic .NET developer experience for verifying EUDI Wallet credentials. A developer should `dotnet add package`, wire one ASP.NET Core endpoint, and run a full verification in **demo mode** within minutes. We win on .NET/Azure ecosystem fit and DX, not novel protocol work.

## Hard rules
1. **Contracts are frozen.** Implement against the interfaces/DTOs tagged `contracts-v0`. Never modify a published contract. If you believe one must change, STOP and flag it — do not edit it.
2. **Stay in your workstream.** Touch only the package(s) you own (see the CLAUDE.md in your directory). Consume other packages only through the frozen contracts.
3. **Never roll your own crypto.** Use platform primitives (`System.Security.Cryptography`, `System.Formats.Cbor`) and `Microsoft.IdentityModel` JWT libraries.
4. **Test everything.** Unit tests per package; verification logic against published spec test vectors; negative tests for tampering, replay, and untrusted issuers.
5. When a spec detail is ambiguous, defer to the **EUDI ARF + HAIP** and leave a `// SPEC:` comment citing the source.

## Spec gotchas (brief §4)
- `dc+sd-jwt`, NOT `vc+sd-jwt`.
- DCQL, NOT Presentation Exchange.
- Issuer key resolution: JWT VC Issuer Metadata **and** X.509.
- Support `direct_post` and `direct_post.jwt` (JWE). Always enforce nonce/state.

## Baseline
.NET 8 LTS (multitarget `net9.0` where trivial). Apache-2.0. Nullable on, warnings-as-errors, analyzers on. Conventional commits.

## Out of scope (commercial layer — do NOT build)
WRPAC / RP registration, full 27-state trust-list aggregation, mdoc/proximity, hosting/dashboards/billing, anything wallet- or issuer-side. (mdoc *remote* is v0.2.)
