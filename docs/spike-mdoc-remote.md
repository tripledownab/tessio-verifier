# Spike: mdoc remote verification for v0.2 (ISO 18013-7)

Date: 2026-07-21. Status: complete, recommendation at the end.

The question: what does it take to verify **mdocs** (ISO mobile documents, the format behind the mobile driving licence and the mdoc flavour of the EUDI PID) presented remotely over OpenID4VP, does .NET carry the cryptography, and how does it fit the contracts-v0 architecture? Proximity flows (BLE/NFC, ISO 18013-5 §8) stay out of scope per the project brief; this is remote only.

## Spec landscape

- **ISO/IEC 18013-5** defines the credential itself: CBOR-encoded, claims grouped in namespaces, each disclosed claim an `IssuerSignedItem` whose digest appears in a **Mobile Security Object (MSO)**. The MSO is signed as **COSE_Sign1** by a Document Signer certificate chaining to an **IACA** root (X.509). Holder binding is a device key in the MSO, proven per presentation with a signature (or MAC) over session data.
- **ISO/IEC 18013-7** (published 2024, updated 2025) defines remote presentment. For our purposes it profiles OpenID4VP; we implement against OpenID4VP 1.0 directly.
- **OpenID4VP 1.0 Annex B.2** is the normative surface: format identifier `mso_mdoc`, the `vp_token` entry is a base64url-encoded CBOR `DeviceResponse`, DCQL uses `meta.doctype_value` (e.g. `org.iso.18013.5.1.mDL`, `eu.europa.ec.eudi.pid.1`) and **two-element claim paths** `[namespace, element]` instead of SD-JWT VC's flat paths. B.2.6 defines the `Handover` and `SessionTranscript` structures that bind the device signature to our request (client_id, nonce, response_uri and the response-encryption key thumbprint feed into it).
- **HAIP** requires **encrypted responses** for mdoc presentations (ECDH-ES, P-256), ES256 as the baseline algorithm and one `DeviceResponse` per DCQL query.

## What .NET gives us (verified by PoC)

Both needed packages are first-party, work on net8.0 and are maintained (10.0.x current):

- **System.Formats.Cbor**: `CborReader`/`CborWriter` including the canonical mode ISO requires for digest computation.
- **System.Security.Cryptography.Cose**: `CoseSign1Message` with embedded verify (the MSO in `issuerAuth`), **detached** verify (`deviceAuth` signs `DeviceAuthenticationBytes` that never travel), ES256 and arbitrary headers (the `x5chain` chain at label 33).

The PoC modeled the three crypto operations end to end: sign and verify an MSO-shaped COSE_Sign1 with an x5chain header, extract and load the chain, round-trip the `valueDigests` map through canonical CBOR, verify a detached device signature and reject a tampered transcript. All green on net8.0 and net9.0. No cryptography needs writing; this satisfies the never-roll-your-own rule entirely.

Two existing investments carry over directly:

- The **ECDH-ES receive side** built for `direct_post.jwt` is exactly what HAIP mandates for mdoc responses. Done.
- The **anchored trust seam**: `ITrustListResolver` receives an X.509 chain, and `StaticTrustListResolver` validates chains against configured anchors. IACA roots are precisely such anchors. The mdoc trust model drops into the existing seam without change.

## Verification pipeline (the v0.2 work)

Per document in the decoded `DeviceResponse`:

1. Verify `issuerAuth` (COSE_Sign1 over the MSO), resolve the Document Signer key from `x5chain`, pass the chain to `ITrustListResolver` (IACA anchoring).
2. Validate the MSO: `docType` matches the DCQL query, `validityInfo` window against the clock, `digestAlgorithm` allowlist.
3. For each disclosed `IssuerSignedItem`, compute its digest and require a match in the MSO `valueDigests` (the mdoc analogue of RFC 9901 disclosure hashing). Unmatched items are rejected.
4. Reconstruct the `SessionTranscript` from our session (client_id, nonce, response_uri, encryption key thumbprint per Annex B.2.6), build `DeviceAuthenticationBytes` and verify `deviceAuth` detached against the device key from the MSO (the mdoc analogue of the KB-JWT).
5. Map disclosed items to `VerificationResult.DisclosedClaims` with namespace-qualified names, same stable error codes.

## Architecture fit

- **Contracts survive untouched** except for one friction point, below. `PresentedCredential` is format-agnostic; a new **`Tessio.Verifier.Core.Mdoc`** package implements the pipeline (keeping Core free of the COSE and CBOR package references), and the AspNetCore layer routes by `Format` (`dc+sd-jwt` vs `mso_mdoc`).
- **DCQL builder** learns two-element paths and `doctype_value`. **Mock mode** gains an mdoc issuer (IACA root plus DS cert, same pattern as `MockCredentialIssuer`). The callback processor and session machinery are unchanged.
- **The friction: `VerificationContext` is a frozen sealed record** carrying nonce, audience and vct. The mdoc `SessionTranscript` additionally needs response_uri and the encryption key thumbprint. It cannot be extended, so v0.2 routes the mdoc path through a richer internal context in the AspNetCore processor while `ICredentialVerifier` remains the SD-JWT surface. That works cleanly, but it is a signal that a future **contracts-v1** should generalize the per-presentation context. Flagging per the contracts rule; no contract change in v0.2.

## Test strategy

Mock mdoc issuer for the offline pipeline (real IACA chain, real device key), spec-derived fixtures where reproducible (ISO 18013-5's annex worked example, EUDI reference issuer output), and the same negative families as SD-JWT: tampered digests, wrong transcript, untrusted IACA, expired MSO, doctype mismatch. Interop against the EUDI reference wallet is the exit criterion before calling v0.2 done: the Handover bytes must match other implementations exactly, and that is proven by interop, not by reading.

## Risks and open questions

- **Handover byte-exactness** is the main interop risk. Annex B.2.6 of the final spec must be implemented against its exact CBOR, and validated against a reference implementation early, not last.
- **deviceMac**: 18013-5 allows MAC-based device auth (ECDH-derived EMacKey) as an alternative to signatures. Start with `deviceSignature` (what remote wallet implementations use), add MAC only if interop demands it.
- **Non-canonical CBOR from wallets**: read leniently, compute digests over the received bytes (the spec hashes the transported `IssuerSignedItemBytes`, so re-encoding is neither needed nor safe).
- Multiple documents per response and the ISO 23220 doctype family: design the parser for a list from day one, ship single-document verification first.

## Recommendation

Proceed. The platform pieces are proven, two of the hardest parts (response decryption, anchored X.509 trust) are already shipped, and the shape mirrors Workstream A closely enough to estimate: the Core.Mdoc pipeline is roughly one Workstream A of effort, plus a smaller integration slice (mock issuer, DCQL, routing). Suggested order: DeviceResponse/MSO parsing with digest checks, then issuerAuth and trust, then SessionTranscript and deviceAuth, then the AspNetCore slice, then reference-wallet interop.
