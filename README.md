# Tessio.Verifier

**The .NET / ASP.NET Core verifier for the EU Digital Identity (EUDI) Wallet.**

[![CI](https://github.com/tripledownab/tessio-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/tripledownab/tessio-verifier/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Tessio.Verifier.AspNetCore.svg)](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Verify credentials presented by EUDI Wallets directly from your .NET backend, over **OpenID4VP 1.0** with **SD-JWT VC** credentials. Native to ASP.NET Core and Azure, with a built-in **demo mode** so you can run a full verification flow today, before any production wallet ships.

> Relying-party (verifier) side only. This library never acts as a wallet or an issuer.

> **Status: the full pipeline runs on `main`.** The quickstart below works end to end. **Mock** mode exercises the real protocol path with a built-in wallet, **Test** mode replays the RFC 9901 conformance vector through the real verifier and **Live** mode waits for real wallets on the callback endpoint (see the [going-live guide](docs/going-live.md)). Version 0.1.3 is [on NuGet](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore) now. Follow [releases](https://github.com/tripledownab/tessio-verifier/releases) for progress.

## Why this exists

The EUDI Wallet arrives under Regulation (EU) 2024/1183: member states must make wallets available by **December 2026**, and regulated relying parties must **accept** them by **December 2027**. The open-source verifier tooling today is Kotlin (walt.id), Rust (SpruceID), and TypeScript (OpenEUDI). If you run on .NET, there hasn't been a native option. This is it.

## What you get (v0.1)

- OpenID4VP 1.0 verifier flow (cross-device / QR), **DCQL** queries, JAR-signed requests (RFC 9101)
- **SD-JWT VC** verification: issuer signature (JWT VC Issuer Metadata and X.509), selective disclosure, key binding (KB-JWT)
- **DEMO / MOCK / TEST** modes so you can build before wallets exist
- Idiomatic ASP.NET Core integration (DI + minimal APIs) and a runnable sample
- A pluggable trust seam (`ITrustListResolver`) for production trust lists

## Install

```bash
dotnet add package Tessio.Verifier.AspNetCore
```

## Quickstart — 5 minutes, DEMO mode

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Demo;          // auto-completes locally, no real wallet needed
    options.RequestedClaims = ["age_over_18"]; // selective disclosure: ask only for what you need
});

var app = builder.Build();

app.MapTessioVerifier();   // request-init, wallet-callback, and result-stream (SSE) endpoints

app.MapGet("/", () => Results.Content(
    """<a href="/verify/start">Start a verification</a>""", "text/html"));

app.Run();
```

Run it, open the page, start a verification, and DEMO mode returns a verified `age_over_18` claim over Server-Sent Events.

## Modes

- **Demo**: auto-completes in seconds, for showcases and first-run experience.
- **Mock**: a built-in mock wallet posts freshly signed credentials through the full verification pipeline, encrypted responses included.
- **Test**: replays the RFC 9901 conformance vector (the spec's German PID example) through the real verifier, so you see the verifier agree with the specification's own bytes.
- **Live**: sessions wait for real wallets on the callback endpoint. [docs/going-live.md](docs/going-live.md) covers the setup: signed requests, trust lists, session stores and response encryption.

## Packages

| Package | Purpose |
| --- | --- |
| `Tessio.Verifier.Core` | Credential verification (SD-JWT VC, disclosures, KB-JWT). No web dependencies. |
| `Tessio.Verifier.OpenId4Vp` | OpenID4VP protocol layer (request build, JAR, response parsing). |
| `Tessio.Verifier.AspNetCore` | DI, endpoints, session management, demo/mock/test modes. |
| `Tessio.Verifier.Trust` | `ITrustListResolver` interface + a basic implementation. |

## Going to production

[docs/going-live.md](docs/going-live.md) walks through the code side: signed requests (Key Vault/HSM included), real trust lists, distributed session stores and shared response-encryption keys. Beyond the code, live verification against real wallets requires a **registered Relying Party** and a **WRPAC** (Wallet Relying Party Access Certificate) from a Qualified Trust Service Provider, plus maintained EU trust lists. This library handles the protocol and credential verification. The trust and compliance layer is provided separately (see `docs/production.md`). Relying parties do **not** need their own HSM/QSCD, since the QTSP holds those.

## Standards

- OpenID4VP 1.0 — <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
- SD-JWT VC — <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc>
- EUDI Architecture & Reference Framework — <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>
- WRPAC profile — ETSI TS 119 475

## Repository

- **Source:** <https://github.com/tripledownab/tessio-verifier>
- **Issues:** <https://github.com/tripledownab/tessio-verifier/issues>
- **Releases:** <https://github.com/tripledownab/tessio-verifier/releases>

## License

Apache-2.0
