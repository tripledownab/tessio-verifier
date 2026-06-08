# Going to production

`Tessio.Verifier` handles the OpenID4VP protocol and SD-JWT VC verification. To verify credentials from **real** EUDI Wallets in production — not just in DEMO/MOCK/TEST mode — you also need to be a recognised Relying Party and to validate against live EU trust lists. This page covers what that involves and how the library supports it.

> Implementation guidance, not legal advice. Registration specifics vary by member state.

## What production requires beyond the protocol

Under **Article 5b of Regulation (EU) 2024/1183 (eIDAS 2.0)**, a service that requests attributes from EUDI Wallets must be a registered Relying Party and authenticate itself with certificates. Two are mandatory:

1. **Relying Party Registration → Registration Certificate (RPRC).** You register with your member state's national authority and appear in a public register stating who you are and which attributes you're authorised to request. Registration produces a Registration Certificate conveying those entitlements.
2. **Wallet Relying Party Access Certificate (WRPAC).** Issued by a **Qualified Trust Service Provider (QTSP)** and profiled in **ETSI TS 119 475**. The wallet checks your WRPAC *before* showing the user a consent screen; if it's missing, expired, or not chained to a provider on the trust list, the wallet refuses the request. A WRPAC can only be obtained after registration is complete.

You do **not** need your own HSM or QSCD — the QTSP holds those. You hold and present the certificate.

## Trust validation

Verifying a presentation in production means validating the issuer's and your own certificates against the EU trust hierarchy:

```
EU List of Trusted Lists (LOTL) → national trusted list → trust service provider → certificate
```

across all 27 member states, kept current as trust lists and the ARF evolve.

In the library this is the `ITrustListResolver` seam (`Tessio.Verifier.Trust`). The open-source build ships a basic file/URL resolver for development. Production needs a resolver that traverses the live LOTL hierarchy and stays current — that is the managed/compliance layer, deliberately kept out of the open-source core.

## Two paths to production

**Self-managed.** Register as a Relying Party in your member state, obtain a WRPAC from a QTSP, and implement a production `ITrustListResolver` against the live 27-state trust lists. You own certificate renewal (WRPACs are typically valid ~1 year), trust-list updates, and audit logging.

**Tessio managed.** The managed service provides the production trust layer on top of this library: registration support, WRPAC procurement and renewal via a QTSP partner, a maintained 27-state trust-list resolver, audit-grade logging, and a hosted verifier endpoint. You keep the same `Tessio.Verifier` APIs; the managed resolver replaces the development one. *(Contact: tessio.eu)*

## Timeline

- **Wallet availability** — member states must provide a certified EUDI Wallet by **6 December 2026**.
- **Mandatory acceptance** — regulated relying parties (banking, financial services, and other designated sectors) must accept wallets by **6 December 2027**.
- **Registration** — national RP registration opens through 2026; WRPAC issuance follows once registers are live. The certificate process takes time, so begin registration as early as your member state allows.

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
