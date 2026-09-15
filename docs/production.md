# Going to production

`Tessio.Verifier` handles the OpenID4VP protocol and SD-JWT VC verification. To verify credentials from **real** EUDI Wallets in production, not just in DEMO/MOCK/TEST mode, you also need to be a recognised Relying Party and to validate against live EU trust lists. This page covers what that involves and how the library supports it.

> Implementation guidance, not legal advice. Registration specifics vary by member state.

## What production requires beyond the protocol

Under **Article 5b of Regulation (EU) 2024/1183 (eIDAS 2.0)**, a service that requests attributes from EUDI Wallets must be a registered Relying Party and authenticate itself with certificates. Two are mandatory:

1. **Relying Party Registration → Registration Certificate (RPRC).** You register with your member state's national authority and appear in a public register stating who you are and which attributes you're authorised to request. Registration produces a Registration Certificate conveying those entitlements.
2. **Wallet Relying Party Access Certificate (WRPAC).** Issued by a **Qualified Trust Service Provider (QTSP)** and profiled in **ETSI TS 119 475**. The wallet checks your WRPAC *before* showing the user a consent screen; if it's missing, expired, or not chained to a provider on the trust list, the wallet refuses the request. A WRPAC can only be obtained after registration is complete.

You do **not** need your own HSM or QSCD: the QTSP holds those. You hold and present the certificate.

## Trust validation

Verifying a presentation in production means validating the issuer's and your own certificates against the EU trust hierarchy:

```
EU List of Trusted Lists (LOTL) → national trusted list → trust service provider → certificate
```

across all 27 member states, kept current as trust lists and the ARF evolve.

**That hierarchy is where the EUDIW profile is going, and it is not where it is today.** The national PID-issuer lists are expected to ride the same ETSI TS 119 612 infrastructure and **are not published yet**, so no resolver can read them, ours included. A live 27-state issuer resolver for wallet credentials is a plan, not a product, whoever is offering it.

What exists, and what this library reads today:

| Source | State |
|---|---|
| The Commission's **age verification trusted list** | Live. Read, refreshed on a schedule, and filtered so an anchor outside its validity window is dropped and named |
| **Pinned anchors** you configure | Live. The route for a pilot or an interoperability issuer, which is how interop testing is done today |
| **National PID-issuer lists** via the LOTL | Not published. Nothing to read |

In the library this is the `ITrustListResolver` seam (`Tessio.Verifier.Trust`). Three implementations already sit behind it, so adding a national-list resolver is a registration change rather than a rewrite.

## Two paths to production

**Self-managed.** Register as a Relying Party in your member state, obtain a WRPAC from a QTSP, and implement an `ITrustListResolver` against whichever lists your profile actually requires. You own certificate renewal (WRPACs are typically valid ~1 year), trust-list updates, and audit logging.

**Tessio managed.** The hosted service runs the trust layer for you: the live age verification trusted list with scheduled refresh and expiry filtering, anchor configuration, audit-grade logging, and a hosted verifier endpoint. You keep the same `Tessio.Verifier` APIs. National issuer lists are added when the Commission publishes them, behind the same seam and with no API change on your side. *(Contact: tessio.eu)*

## Timeline

*Both dates derive from the implementing acts, never from the regulation itself. The acts were published 4 December 2024 and entered into force on the twentieth day after, so the clock starts **24 December 2024**. Verified against the Official Journal, not a summary.*

- **Wallet availability.** Article 5a(1) gives member states 24 months, so **24 December 2026**.
- **Mandatory acceptance.** Article 5f(2) gives 36 months, so **24 December 2027**. It binds private relying parties in eleven named sectors (transport, energy, banking, financial services, social security, health, drinking water, postal services, digital infrastructure, education, telecommunications), **only upon the voluntary request of the user**, and **micro and small enterprises are excluded**. If you are not in those sectors, this date is not your obligation.
- **Registration.** National RP registration opens through 2026; WRPAC issuance follows once registers are live. The certificate process takes time, so begin registration as early as your member state allows.

## Production checklist

- [ ] Confirm which flows will accept the wallet (age verification, KYC onboarding, SCA, etc.).
- [ ] Register as a Relying Party with your national authority; obtain the Registration Certificate.
- [ ] Obtain a WRPAC from a QTSP (or via the Tessio managed service).
- [ ] Wire a production `ITrustListResolver` (self-managed) or switch to the managed resolver.
- [ ] Enforce nonce/state, audit logging, and certificate renewal.
- [ ] Run the conformance harness against the EU reference wallet before go-live.

## References

- Regulation (EU) 2024/1183 (eIDAS 2.0): <https://eur-lex.europa.eu/eli/reg/2024/1183/oj>
- WRPAC profile: ETSI TS 119 475
- EUDI Architecture & Reference Framework: <https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework>
- OpenID4VP 1.0: <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html>
