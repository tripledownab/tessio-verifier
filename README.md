# Tessio.Verifier

**The .NET / ASP.NET Core verifier for the EU Digital Identity (EUDI) Wallet.**

[![CI](https://github.com/tripledownab/tessio-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/tripledownab/tessio-verifier/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Tessio.Verifier.AspNetCore.svg)](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Verify credentials presented by EUDI Wallets directly from your .NET backend, over **OpenID4VP 1.0** with **SD-JWT VC** and **mdoc** credentials. Native to ASP.NET Core and Azure, with a built-in **demo mode** so you can run a full verification flow today, before any production wallet ships.

> Relying-party (verifier) side only. This library never acts as a wallet or an issuer.

> **Status: the full pipeline runs on `main`.** The quickstart below works end to end. **Mock** mode exercises the real protocol path with a built-in wallet, **Test** mode replays the RFC 9901 conformance vector through the real verifier and **Live** mode waits for real wallets on the callback endpoint (see the [going-live guide](docs/going-live.md)). Version 0.9.1 is [on NuGet](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore), and 0.9.0 tightened how a pinned trust anchor's own validity window is read, so upgrade. 0.8.0 completed the **W3C Digital Credentials API transport** (ISO/IEC 18013-7 Annex C): `Iso18013AnnexC` builds the `{deviceRequest, encryptionInfo}` request pair and opens the HPKE-encrypted response, the builders reproduce the profile's published example byte for byte, the HPKE suite reproduces RFC 9180's own test vectors, device authentication verifies over an externally built session transcript, and the mock wallet answers the exchange offline. 0.8.0 settles the session transcript against a real wallet: one transcript, the plain form, for both the response encryption and the device signature (0.7.0 used a variant that a shipping wallet cannot decrypt, so upgrade). Earlier: 0.5.0 added `AvPresentationRequestBuilder`, which carries DCQL in plain query parameters and sends no request object because that profile does not use JAR, and 0.6.0 reads those parameters back, so the credential format, the docType and the `response_uri` a response is verified against come from the session's own request under either encoding. The verification seam for self-driving and multi-tenant hosts landed in 0.3.0: one process verifies wallet callbacks for many tenants, each against its own request (see the [self-driving and multi-tenant guide](docs/self-driving-and-multi-tenant.md)). **SD-JWT VC** and **mso_mdoc** (ISO 18013-5/-7 mobile documents, e.g. the mDL) are verified through the same pipeline, validated against external artifacts at every layer. Follow [releases](https://github.com/tripledownab/tessio-verifier/releases) for progress.

## Why this exists

The EUDI Wallet arrives under Regulation (EU) 2024/1183. Member states must make a wallet available by **24 December 2026**. From **24 December 2027** a relying party that is required to use strong user authentication for online identification must also accept a wallet, and only when the user chooses to present one. Micro and small enterprises are out of scope, and both dates run from the implementing acts that entered into force on 24 December 2024 rather than from the regulation itself.

If you verify those credentials from .NET, this library does the protocol and the cryptography and then proves it against tests written by someone else. It passes the OpenID Foundation conformance suite for OpenID4VP 1.0 HAIP verifiers in both credential formats the wallet uses, and every run is pinned to the source tree it ran against in `conformance-record.json`.

## What you get

- OpenID4VP 1.0 verifier flow (cross-device / QR), **DCQL** queries, JAR-signed requests (RFC 9101)
- **SD-JWT VC** verification: issuer signature (JWT VC Issuer Metadata and X.509), selective disclosure, key binding (KB-JWT), transaction data
- **mdoc** (`mso_mdoc`) verification: ISO 18013-5/-7 mobile documents like the mDL, validated against the spec's own vectors and an independent implementation
- **W3C Digital Credentials API transport** (ISO/IEC 18013-7 Annex C): build the `{deviceRequest, encryptionInfo}` request pair, open the HPKE-encrypted response (RFC 9180, checked against the RFC's own vectors) and verify device auth over the Annex C session transcript (`Iso18013AnnexC`)
- Token Status List revocation checking
- **Demo / Mock / Test / Live** modes so you can build before wallets exist, then serve real ones
- Idiomatic ASP.NET Core integration (DI + minimal APIs) and a runnable sample
- **Self-driving and multi-tenant hosting**: verify wallet callbacks for many tenants in one process, each against its own request (`IWalletResponseVerifier`)
- A pluggable trust seam (`ITrustListResolver`) for production trust lists

## Install

```bash
dotnet add package Tessio.Verifier.AspNetCore
```

Runs on **.NET 8, 9 and 10**. The packages target .NET 8 and .NET 10 (both LTS); apps on .NET 9 use the .NET 8 build.

## Quickstart in 5 minutes (DEMO mode)

```csharp
using Tessio.Verifier.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Demo;          // auto-completes locally, no real wallet needed
    options.RequestedClaims = ["age_over_18"]; // selective disclosure: ask only for what you need
});

var app = builder.Build();

app.MapTessioVerifier();   // request-init, wallet-callback and result-stream (SSE) endpoints

app.MapGet("/", () => Results.Content(
    """<a href="/verify/start">Start a verification</a>""", "text/html"));

app.Run();
```

Run it, open the page, start a verification, and DEMO mode returns a verified `age_over_18` claim over Server-Sent Events.

## Modes

- **Demo**: auto-completes in seconds, for showcases and first-run experience.
- **Mock**: a built-in mock wallet posts freshly signed credentials through the full verification pipeline, encrypted responses included. Set `options.CredentialFormat = "mso_mdoc"` to run the mdoc pipeline instead of SD-JWT VC.
- **Test**: replays the RFC 9901 conformance vector (the spec's German PID example) through the real verifier, so you see the verifier agree with the specification's own bytes.
- **Live**: sessions wait for real wallets on the callback endpoint. [docs/going-live.md](docs/going-live.md) covers the setup: signed requests, trust lists, session stores and response encryption.

## Packages

| Package | Purpose |
| --- | --- |
| `Tessio.Verifier.Core` | Credential verification (SD-JWT VC, disclosures, KB-JWT). No web dependencies. |
| `Tessio.Verifier.Core.Mdoc` | mdoc verification (ISO 18013-5/-7: MSO, digests, device auth). |
| `Tessio.Verifier.OpenId4Vp` | OpenID4VP protocol layer (request build, JAR, response parsing, `Dcql` query builders). |
| `Tessio.Verifier.AspNetCore` | DI, endpoints, session management, the multi-tenant verification seam, demo/mock/test modes. |
| `Tessio.Verifier.Trust` | `ITrustListResolver` interface + a basic implementation. |

## Going to production

[docs/going-live.md](docs/going-live.md) walks through the code side: signed requests (Key Vault/HSM included), real trust lists, distributed session stores and shared response-encryption keys. For self-driving or multi-tenant hosting (your own store, one process serving many tenants), see [docs/self-driving-and-multi-tenant.md](docs/self-driving-and-multi-tenant.md). Beyond the code, live verification against real wallets requires a **registered Relying Party** and a **WRPAC** (Wallet Relying Party Access Certificate) from a Qualified Trust Service Provider, plus maintained EU trust lists. This library handles the protocol and credential verification. The trust and compliance layer is provided separately (see `docs/production.md`). Relying parties do **not** need their own HSM/QSCD, since the QTSP holds those.

## Standards

- OpenID4VP 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
- SD-JWT VC: <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc>
- EUDI Architecture & Reference Framework: <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>
- WRPAC profile: ETSI TS 119 475

## Free validators

When a credential will not verify, the quickest way to find out why is to look at it outside your own
code. These are free, need no account, and cover the formats this library handles:

| Validator | What it answers |
| --- | --- |
| [SD-JWT VC Validator](https://labs.tessio.eu/sd-jwt) | Does each disclosure bind to a signed `_sd` digest? |
| [mdoc / mDL Validator](https://labs.tessio.eu/mdoc) | Is the Mobile Security Object intact, and does the IACA chain hold? |
| [eIDAS Signature Validator](https://labs.tessio.eu/ades) | Is this PAdES, CAdES or JAdES signature valid, and is it qualified? |
| [EU Trusted List Checker](https://labs.tessio.eu/trusted-list) | Is this certificate a qualified CA on an EU trusted list? |
| [EUDI Trusted Entity Checker](https://labs.tessio.eu/lote) | Does the EUDI ecosystem trust this certificate, and in which role? |

The SD-JWT VC validator runs in your browser by default, so nothing you paste leaves the machine
unless you opt into issuer-trust anchoring. The other four check against EU trust data that only a
server can fetch, so they post what you give them to the hosted service. Each tool states which it is
doing. They are built by the maintainers of this library, on the same verification engine, and
nothing here depends on them.

## Repository

- **Source:** <https://github.com/tripledownab/tessio-verifier>
- **Issues:** <https://github.com/tripledownab/tessio-verifier/issues>
- **Releases:** <https://github.com/tripledownab/tessio-verifier/releases>

## License

Apache-2.0
