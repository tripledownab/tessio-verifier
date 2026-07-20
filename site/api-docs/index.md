---
_layout: landing
title: Tessio.Verifier API reference
---

# Tessio.Verifier API reference

The public API for verifying EU Digital Identity (EUDI) Wallet credentials in ASP.NET Core — the frozen
contracts plus the implementation surface as it lands (`SdJwtVcVerifier`, demo-mode hosting, the in-memory
session store).

The contracts are frozen at tag **[`contracts-v0`](https://github.com/tripledownab/tessio-verifier/releases/tag/contracts-v0)**;
everything else follows [releases](https://github.com/tripledownab/tessio-verifier/releases).

## Packages

| Package | Purpose |
| --- | --- |
| [Tessio.Verifier.Core](xref:Tessio.Verifier.Core) | Credential verification (SD-JWT VC, disclosures, KB-JWT). No web dependencies. |
| [Tessio.Verifier.OpenId4Vp](xref:Tessio.Verifier.OpenId4Vp) | OpenID4VP 1.0 protocol layer (DCQL + JAR build, response parse). |
| [Tessio.Verifier.AspNetCore](xref:Tessio.Verifier.AspNetCore) | DI extensions, minimal-API endpoints, session store, demo/mock/test modes. |
| [Tessio.Verifier.Trust](xref:Tessio.Verifier.Trust) | `ITrustListResolver` seam — basic dev resolver in OSS, managed resolver in the commercial layer. |

## Where to start

- New to OpenID4VP / SD-JWT VC? Read the [marketing landing](https://verifier.tessio.eu/) first.
- Building a verifier? `dotnet add package Tessio.Verifier.AspNetCore` and follow the [README quickstart](https://github.com/tripledownab/tessio-verifier#quickstart--5-minutes-demo-mode).
- Plugging your own session store or trust list? Browse [API reference](xref:Tessio.Verifier.AspNetCore.ISessionStore) for the relevant interface.
