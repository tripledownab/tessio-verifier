# Contributing to Tessio.Verifier

Thanks for your interest. This page covers what you need to build, test and land a change.

## Development setup

- .NET 10 SDK (`global.json` pins the exact build SDK; the net 10 SDK builds both target frameworks). The solution multitargets net8.0 (LTS floor, broad reach) and net10.0 (current LTS).
- Any editor. No other tooling is required.

```bash
dotnet build Tessio.Verifier.sln
dotnet test Tessio.Verifier.sln
```

The build treats warnings as errors with analyzers on. If it builds clean locally, CI will agree.

## Ground rules

- **Frozen contracts.** Interfaces and DTOs marked `FROZEN contract (contracts-v0)` in the source must not change. If you believe one has to, open an issue first; do not send a PR that edits them.
- **No custom cryptography.** Use platform primitives (`System.Security.Cryptography`, `System.Formats.Cbor`, `System.Security.Cryptography.Cose`) and the `Microsoft.IdentityModel` libraries. PRs that hand-roll crypto will not be merged.
- **Spec fidelity.** Where the code implements a specification detail, cite it with a `// SPEC:` comment naming the document and section. When a spec is ambiguous, the EUDI ARF and HAIP interpretations win.
- **Tests are required.** New behavior needs tests, including negatives (tampering, replay, malformed input). Verification logic changes should be checked against published spec test vectors where they exist. The fuzz suites must stay green.
- **Stable error codes.** `VerificationError.Code` values are append-only observable behavior. Never rename or remove one.

## Commit and PR conventions

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, with scope, e.g. `fix(core): …`).
- Keep PRs focused; one concern per PR.
- The `ci` workflow (Linux) must pass. A Windows leg runs on a weekly schedule and on demand.

## Reporting security issues

Do not open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md) for the disclosure process.

## Scope

This library is the relying-party (verifier) side only. Wallet-side, issuer-side, proximity (BLE/NFC) flows and production trust-list infrastructure are out of scope; see the README for the project boundaries.

## License

Contributions are accepted under Apache-2.0, the project license.
