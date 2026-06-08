# Verifying EU Digital Identity Wallet credentials in .NET: a relying party's guide

If you run a business on the Microsoft stack and you take identity checks today — age gating, KYC onboarding, strong customer authentication — a deadline is heading your way. Under the EU's revised eIDAS regulation (Regulation (EU) 2024/1183), every member state must make a European Digital Identity (EUDI) Wallet available by December 2026, and regulated sectors must *accept* those wallets roughly a year later, in December 2027. When that lands, your users will expect to prove who they are by tapping a wallet on their phone instead of uploading a photo of a passport.

The catch for .NET teams: almost every open-source toolkit for the *relying party* side — the business doing the verifying — has been written in something other than .NET. The official reference verifier is Kotlin. SpruceID's stack is Rust. The most prominent new open-source SDK is TypeScript. If your backend is ASP.NET Core, you've been left translating concepts across ecosystems. This guide walks through what verification actually involves and what it looks like in idiomatic .NET.

## What a relying party actually does

There are three roles in this ecosystem. The **issuer** is a government or trusted authority that signs a credential (say, a national ID). The **holder** is the citizen carrying it in their wallet app. The **relying party** — you — requests and verifies attributes from that wallet. You never touch the issuer's systems directly; you verify cryptographically.

The conversation between your service and the wallet happens over a protocol called **OpenID4VP** (OpenID for Verifiable Presentations), which reached its 1.0 release in 2025. A typical remote flow looks like this:

1. Your backend builds a presentation request describing exactly which attributes you need — and only those. The query format is **DCQL** (the Digital Credentials Query Language), which replaced the older Presentation Exchange syntax.
2. You sign that request (a JWT-Secured Authorization Request, per RFC 9101) and present it to the user as a QR code or deep link.
3. The wallet shows the user a consent screen — "this service wants to confirm you are over 18" — and, if they agree, returns a signed, encrypted response to your endpoint.
4. Your backend verifies the response and reads the disclosed claims.

The principle running through all of it is **data minimisation**. You ask for `age_over_18`, not a date of birth; you ask for a name, not an entire identity document. The wallet enforces this, and so does the regulation.

## The credential format you'll verify

For online flows, the dominant format is **SD-JWT VC** — a Selective Disclosure JWT Verifiable Credential. It's a JWT the issuer signs over a set of claims, where each claim can be individually revealed or withheld by the holder. Verifying one means: validate the issuer's signature, reconstruct and hash-check the disclosed claims, and — when present — verify the Key Binding JWT that proves the wallet holder is the legitimate subject.

One detail that trips people up: the media type and `typ` header changed from `vc+sd-jwt` to **`dc+sd-jwt`** in late 2024 to avoid a clash with the W3C credential model. Older tutorials still show the old value. Use `dc+sd-jwt`.

Resolving the issuer's public key happens one of two ways: **JWT VC Issuer Metadata** (a web lookup when the issuer identifier is an HTTPS URL) or an **X.509 certificate chain** carried in the token header. A complete verifier supports both.

## What it looks like in ASP.NET Core

The point of a native library is that none of the above should leak into your application code. Wiring up a verifier should feel like wiring up any other ASP.NET Core service:

```csharp
builder.Services.AddTessioVerifier(options =>
{
    options.Mode = VerifierMode.Demo;          // run the full flow before real wallets exist
    options.RequestedClaims = ["age_over_18"];
});

// ...
app.MapTessioVerifier();   // request-init, wallet-callback, result-stream endpoints
```

A demo mode matters more than it sounds. As of mid-2026 there are no production wallets in citizens' hands yet, so you cannot test against a live one. Being able to run a complete request-and-verify cycle locally — and then switch to fixtures for integration tests — is the difference between preparing now and waiting until the rollout forces your hand.

## The part that isn't code

Verification logic is necessary but not sufficient. To make live requests against real wallets, you also have to be a *recognised* relying party. That means two things, both under Article 5b of the regulation:

- **Register** with your national authority. You'll appear in a public register stating who you are and which attributes you're authorised to request. You then receive a Registration Certificate.
- **Obtain a WRPAC** (Wallet Relying Party Access Certificate) from a Qualified Trust Service Provider. The wallet checks this certificate *before* it shows the user a consent screen; if it's missing, expired, or not chained to a trusted provider, the wallet simply refuses.

The good news for developers: you do **not** need specialised hardware. The QTSP holds the HSMs; you just use the certificate to authenticate your requests. The WRPAC profile is defined in ETSI TS 119 475, finalised in late 2025.

Registration portals weren't live across member states as of early 2026 and are expected to open through the middle of the year, which leaves a tight window before the December launch. If you'll need to be ready, the certificate paperwork is the long pole — start it early.

## What to do now

If you're on .NET and you'll be a relying party, three steps are worth taking this quarter. First, map which of your identity flows the wallet will touch — age checks and KYC onboarding are the obvious ones. Second, prototype the verification flow in demo mode so your team understands the shape of it before the deadline pressure arrives. Third, begin the registration and WRPAC conversation with a trust service provider, because that timeline is outside your control.

The protocol is settled, the formats are settled, and the deadline is fixed. The only question for a .NET shop is whether you build the plumbing yourself or start from something native. We've open-sourced a verifier so you don't have to translate from Kotlin — the repository and a five-minute quickstart are linked below.

*Tessio.Verifier is an Apache-2.0 licensed .NET/ASP.NET Core verifier for the EUDI Wallet. [Repository link.]*
