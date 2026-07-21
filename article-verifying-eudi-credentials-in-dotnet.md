# Verifying EU Digital Identity Wallet credentials in .NET: a relying party's guide

If you run a business on the Microsoft stack and you take identity checks today, whether that is age gating, KYC onboarding or strong customer authentication, a deadline is heading your way. Under the EU's revised eIDAS regulation (Regulation (EU) 2024/1183), every member state must make a European Digital Identity (EUDI) Wallet available by December 2026, and regulated sectors must *accept* those wallets roughly a year later, in December 2027. When that lands, your users will expect to prove who they are by tapping a wallet on their phone instead of uploading a photo of a passport.

The catch for .NET teams: almost every open-source toolkit for the *relying party* side, the business doing the verifying, has been written in something other than .NET. The official reference verifier is Kotlin. SpruceID's stack is Rust. The most prominent new open-source SDK is TypeScript. If your backend is ASP.NET Core, you have been left translating concepts across ecosystems. This guide walks through what verification actually involves and what it looks like in idiomatic .NET.

## What a relying party actually does

There are three roles in this ecosystem. The **issuer** is a government or trusted authority that signs a credential (say, a national ID). The **holder** is the citizen carrying it in their wallet app. The **relying party**, you, requests and verifies attributes from that wallet. You never touch the issuer's systems directly; you verify cryptographically.

The conversation between your service and the wallet happens over **OpenID4VP** (OpenID for Verifiable Presentations), which reached its 1.0 release in July 2025. A typical remote flow looks like this:

1. Your backend builds a presentation request describing exactly which attributes you need, and only those. The query format is **DCQL** (the Digital Credentials Query Language), which replaced the older Presentation Exchange syntax.
2. You sign that request (a JWT-Secured Authorization Request, per RFC 9101) and present it to the user as a QR code or deep link.
3. The wallet shows the user a consent screen ("this service wants to confirm you are over 18") and, if they agree, posts a signed, usually encrypted response to your endpoint.
4. Your backend verifies the response and reads the disclosed claims.

The principle running through all of it is **data minimisation**. You ask for `age_over_18`, not a date of birth; you ask for a name, not an entire identity document. The wallet enforces this, and so does the regulation.

## The credential format you'll verify

For online flows, the dominant format is **SD-JWT VC**, a Selective Disclosure JWT Verifiable Credential. The underlying SD-JWT mechanism was published as RFC 9901 in 2025. It is a JWT the issuer signs over a set of claim hashes, where each claim can be individually revealed or withheld by the holder. Verifying one means validating the issuer's signature, reconstructing and hash-checking the disclosed claims, verifying the Key Binding JWT that proves the wallet holder is the legitimate subject and, when the credential carries a status reference, checking a Token Status List to confirm the issuer has not revoked it.

One detail that trips people up: the media type and `typ` header changed from `vc+sd-jwt` to **`dc+sd-jwt`** in late 2024 to avoid a clash with the W3C credential model. Older tutorials still show the old value. Use `dc+sd-jwt`.

Resolving the issuer's public key happens one of two ways: **JWT VC Issuer Metadata** (a web lookup when the issuer identifier is an HTTPS URL) or an **X.509 certificate chain** carried in the token header. A complete verifier supports both, and the X.509 path hides a trap worth spelling out. The signing key arrives inside the credential itself, so a trust list that only matches issuer *names* proves nothing there: anyone can put a trusted issuer's name in a self-signed certificate. For X.509-resolved credentials your trust decision has to anchor the presented chain on certificates you actually trust. We shipped that mistake ourselves in an early version, caught it in review and now reject unanchored chains by default. If you build or buy a verifier, test it with a self-signed certificate that impersonates a trusted issuer and see what happens.

## Two things .NET does not give you

Most of a verifier sits on solid platform ground: `System.Security.Cryptography` for the primitives and the `Microsoft.IdentityModel` stack for JWT handling. Two gaps surprised us.

First, encrypted responses. The EU's high-assurance profile has wallets encrypt their responses to your public key using ECDH-ES key agreement (JWE). The IdentityModel libraries can *send* ECDH-ES tokens but, as of the current release, cannot receive them; the decryption side simply is not shipped. A production verifier has to implement the receive side itself against RFC 7518, deriving the shared key from the wallet's ephemeral public key. That is agreement plumbing around platform primitives, not novel cryptography, but it is exactly the kind of gap you only discover deep into an integration.

Second, conformance material. Specs come with worked examples, and RFC 9901 includes a complete German PID presentation with recursive disclosures and key binding. Wiring those immutable, specification-published bytes into your test suite as a permanent regression gate is the cheapest confidence you will ever buy: if your verifier agrees with the spec's own example, byte for byte, whole classes of implementation drift become impossible.

## What it looks like in ASP.NET Core

The point of a native library is that none of the above should leak into your application code. Wiring up a verifier should feel like wiring up any other ASP.NET Core service:

```bash
dotnet add package Tessio.Verifier.AspNetCore
```

```csharp
builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Demo;          // run the full flow before real wallets exist
    options.RequestedClaims = ["age_over_18"];
});

// ...
app.MapTessioVerifier();   // request-init, QR start page, wallet-callback, result-stream endpoints
```

Operating modes matter more than they sound. As of mid-2026 there are no production wallets in citizens' hands, so you cannot test against a live one. Tessio ships four:

- **Demo** auto-completes a session locally, so a first run works in minutes.
- **Mock** runs a built-in wallet through the real protocol path: freshly signed credentials, encrypted responses, the works, fully offline.
- **Test** replays the RFC 9901 conformance vector through the real verifier, so you can watch your stack agree with the specification's own example in a browser.
- **Live** waits for real wallets, and refuses to start if the demo trust list or unsigned request builder is still configured, so a demo setup cannot quietly reach production.

Being able to run the complete request-and-verify cycle locally today, then flip one enum value when wallets arrive, is the difference between preparing now and waiting until the rollout forces your hand.

## The part that isn't code

Verification logic is necessary but not sufficient. To make live requests against real wallets, you also have to be a *recognised* relying party. That means two things, both under Article 5b of the regulation:

- **Register** with your national authority. You will appear in a public register stating who you are and which attributes you are authorised to request. You then receive a Registration Certificate.
- **Obtain a WRPAC** (Wallet Relying Party Access Certificate) from a Qualified Trust Service Provider. The wallet checks this certificate *before* it shows the user a consent screen; if it is missing, expired or not chained to a trusted provider, the wallet simply refuses.

The good news for developers: you do **not** need specialised hardware. The QTSP holds the HSMs; you just use the certificate to authenticate your requests. The WRPAC profile is defined in ETSI TS 119 475, finalised in late 2025.

Member-state registration portals have been opening gradually through 2026, which leaves a tight window before the December launch. If you will need to be ready, the certificate paperwork is the long pole. Start it early.

## What to do now

If you are on .NET and you will be a relying party, three steps are worth taking this quarter. First, map which of your identity flows the wallet will touch; age checks and KYC onboarding are the obvious ones. Second, prototype the verification flow in demo mode so your team understands the shape of it before the deadline pressure arrives. Third, begin the registration and WRPAC conversation with a trust service provider, because that timeline is outside your control.

The protocol is settled, the formats are settled and the deadline is fixed. The only question for a .NET shop is whether you build the plumbing yourself or start from something native. We have open-sourced a verifier so you do not have to translate from Kotlin: it is on NuGet today, verified against the spec's own test vectors, with a guide covering the whole path from demo mode to live wallets.

*Tessio.Verifier is an Apache-2.0 licensed .NET/ASP.NET Core verifier for the EUDI Wallet by Triple Down AB. Source: [github.com/tripledownab/tessio-verifier](https://github.com/tripledownab/tessio-verifier). Packages: [nuget.org/packages/Tessio.Verifier.AspNetCore](https://www.nuget.org/packages/Tessio.Verifier.AspNetCore). Docs and the going-live guide: [verifier.tessio.eu](https://verifier.tessio.eu/).*
