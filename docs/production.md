# Going to production

`Tessio.Verifier` handles the OpenID4VP protocol and SD-JWT VC and mdoc verification. To verify credentials from **real** EUDI Wallets in production, not just in DEMO/MOCK/TEST mode, you also need to be a recognised Relying Party and to validate against live EU trust lists. This page covers what that involves and how the library supports it.

> Implementation guidance, not legal advice. Registration specifics vary by member state.

## What production requires beyond the protocol

**Article 5b(1) of Regulation (EU) 2024/1183 (eIDAS 2.0)**: a relying party that intends to rely upon EUDI Wallets "shall register in the Member State where it is established". Implementing Regulation (EU) 2025/848 sets out what follows from registration:

1. **Registration.** You register with your member state, which publishes what you declared, including the data you intend to request (2024/1183 Article 5b(2) and (5)).
2. **Wallet-relying party access certificate (WRPAC).** Each member state authorises at least one certificate authority to issue them, and it issues them to registered relying parties only (2025/848 Article 7(1) and (2)). The text names an authorised certificate authority, not a qualified trust service provider. The certificate is profiled in **ETSI TS 119 475** under the policy in **ETSI TS 119 411-8**. It is what signs your request, so a wallet that checks reader authentication refuses a request without one.
3. **Registration certificate.** Each member state authorises at least one certificate authority to issue them, "in an automated manner and without undue delay after the registration", and each one expresses an intended use you registered (2025/848 Article 8(1) and (2), as replaced by Implementing Regulation (EU) 2026/1730). The original 2025/848 made these optional; the amendment did not.

**Not every profile signs.** The EU Age Verification profile sends unsigned requests: "Reader authentication is not required and therefore is out of scope of this profile" (AV technical specification, Annex A). An age check under that profile needs no access certificate.

**Keys.** You hold the private key that signs your requests. Whether it must sit in a secure device depends on your certificate provider's terms.

## Trust validation

Verifying a presentation in production means validating the issuer's and your own certificates against the EU trust hierarchy:

```
EU List of Trusted Lists (LOTL) → national trusted list → trust service provider → certificate
```

across all 27 member states, kept current as trust lists and the ARF evolve.

**That hierarchy is where the EUDIW profile is going, and it is not where it is today.** A production list of PID providers is **not published yet**, so there is nothing for a resolver to read, this library's included.

What exists today. The library reads none of these by itself: it gives you the `ITrustListResolver` seam and a static resolver, and you, or a hosted service, connect a source behind it.

| Source | State |
|---|---|
| The Commission's **age verification trusted list** | Published. Read it on a schedule and drop an anchor outside its validity window |
| **Pinned anchors** you configure | Available. The route for a pilot or an interoperability issuer, which is how interop testing is done today |
| A **production PID provider list** | Not published. Nothing to read |

In the library this is the `ITrustListResolver` seam (`Tessio.Verifier.Trust`), with `StaticTrustListResolver` as the shipped implementation. A resolver for any other list is a class behind the same interface, registered in DI, not a change to the verification pipeline.

## Two paths to production

**Self-managed.** Register as a Relying Party in your member state, obtain a WRPAC from a certificate authority your member state has authorised if your profile signs its requests, and implement an `ITrustListResolver` against whichever lists your profile actually requires. You own certificate renewal, trust-list updates, and audit logging.

**Tessio managed.** The hosted service runs the trust layer for you: the live age verification trusted list with scheduled refresh and expiry filtering, anchor configuration, audit-grade logging, and a hosted verifier endpoint. You keep the same `Tessio.Verifier` APIs. National issuer lists are added when the Commission publishes them, behind the same seam and with no API change on your side. *(Contact: tessio.eu)*

## Timeline

*Both dates derive from the implementing acts, never from the regulation itself. The acts were published 4 December 2024 and entered into force on the twentieth day after, so the clock starts **24 December 2024**. Verified against the Official Journal, not a summary.*

- **Wallet availability.** Article 5a(1) gives member states 24 months, so **24 December 2026**.
- **Mandatory acceptance.** Article 5f(2) gives 36 months, so **24 December 2027**. It binds private relying parties in eleven named sectors (transport, energy, banking, financial services, social security, health, drinking water, postal services, digital infrastructure, education, telecommunications), **only upon the voluntary request of the user**, and **micro and small enterprises are excluded**. If you are not in those sectors, this date is not your obligation.
- **Registration.** National RP registration opens through 2026; WRPAC issuance follows once registers are live. The certificate process takes time, so begin registration as early as your member state allows.

## Production checklist

- [ ] Confirm which flows will accept the wallet (age verification, KYC onboarding, SCA, etc.).
- [ ] Register as a Relying Party in your member state; obtain a registration certificate where your member state issues them.
- [ ] If your profile signs requests, obtain a WRPAC from a certificate authority your member state has authorised (or via the Tessio managed service).
- [ ] Wire a production `ITrustListResolver` (self-managed) or switch to the managed resolver.
- [ ] Enforce nonce/state, audit logging, and certificate renewal.
- [ ] Run the OpenID Foundation conformance suite against your deployment (`tools/conformance-harness` shows how), and complete a check with a real wallet before go-live.

## References

- Regulation (EU) 2024/1183 (eIDAS 2.0): <https://eur-lex.europa.eu/eli/reg/2024/1183/oj>
- Implementing Regulation (EU) 2025/848, relying party registration: <https://eur-lex.europa.eu/eli/reg_impl/2025/848/oj>
- WRPAC profile: ETSI TS 119 475. Certificate policy: ETSI TS 119 411-8
- EU Age Verification technical specification: <https://github.com/eu-digital-identity-wallet/av-doc-technical-specification>
- EUDI Architecture & Reference Framework: <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>
- OpenID4VP 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
