# START HERE — running the Tessio.Verifier build in Claude Code

Operator runbook. Follow top to bottom. Assumes the Claude Code CLI and the .NET 8 SDK are installed.

---

## 0. Scaffold the repo

```bash
mkdir veridio-verifier && cd veridio-verifier
git init
mkdir -p docs
# Place the agent brief at  docs/agent-brief.md
# Place the provided        CLAUDE.md  at the repo root
git add . && git commit -m "chore: project context + agent brief"
```

The root `CLAUDE.md` is loaded into every session and every worktree automatically, so all agents inherit the rules.

---

## 1. Phase 0 — contracts first (single session, on `main`, DO NOT parallelize)

```bash
claude
```

Switch to **Plan mode**, then paste:

> Build per `docs/agent-brief.md`. **Phase 0 only**: create the solution and the five projects (brief §5), implement the frozen contract interfaces and DTOs (brief §6) exactly — compiling, no logic — and set up CI (build, test, pack). Then commit and tag `contracts-v0`. Do not implement any workstream.

Confirm it builds and the tag exists before continuing:

```bash
dotnet build && git tag   # expect: contracts-v0
```

---

## 2. Fan out — one worktree per workstream

Open one terminal per workstream (run as many concurrently as you can supervise):

```bash
claude --worktree ws/a-core
claude --worktree ws/b-openid4vp
claude --worktree ws/c-aspnetcore
claude --worktree ws/d-trust
claude --worktree ws/e-sample
```

Drop the matching per-workstream `CLAUDE.md` (below) into each package directory, then seed each session with the seed prompt.

### Seed prompt (swap the letter/package per workstream)

> You own **Workstream A — `Tessio.Verifier.Core`** per `docs/agent-brief.md` §6. Implement only this package against the committed `contracts-v0`. Never modify a published contract. Write unit tests including SD-JWT VC spec test vectors and negative cases. Run the tests and commit to this worktree's branch when green.

### Per-workstream CLAUDE.md files

**`src/Tessio.Verifier.Core/CLAUDE.md`**
```
# Workstream A — Tessio.Verifier.Core
Credential verification only. No web/protocol code, no other packages.
Implement: SD-JWT VC parse; issuer signature via JWT VC Issuer Metadata AND X.509;
disclosure reconstruction + hash checks; KB-JWT verification; claim extraction.
Produce VerificationResult. Consume ITrustListResolver (contracts-v0).
Test against published SD-JWT VC vectors + negatives (tampered sig, bad disclosure, missing/expired nonce).
Gotcha: dc+sd-jwt, not vc+sd-jwt.
```

**`src/Tessio.Verifier.OpenId4Vp/CLAUDE.md`**
```
# Workstream B — Tessio.Verifier.OpenId4Vp
OpenID4VP 1.0 protocol layer only.
Implement: DCQL request build; JAR-signed request object (RFC 9101); request_uri by-value/by-reference;
response parsing for direct_post and direct_post.jwt (JWE decrypt); vp_token extraction.
Hand parsed credentials to Core via ICredentialVerifier. Enforce nonce/state/replay.
Gotcha: DCQL, not Presentation Exchange.
```

**`src/Tessio.Verifier.AspNetCore/CLAUDE.md`**
```
# Workstream C — Tessio.Verifier.AspNetCore
DI, endpoints, sessions, modes.
Implement: AddTessioVerifier + MapTessioVerifier (minimal APIs); ISessionStore (in-memory default);
SSE result stream; DEMO/MOCK/TEST mode providers.
DEMO/MOCK/TEST are HIGH priority — no real wallets exist yet.
Depend only on OpenId4Vp contracts.
```

**`src/Tessio.Verifier.Trust/CLAUDE.md`**
```
# Workstream D — Tessio.Verifier.Trust
Trust seam only. Keep it minimal — this is the commercial-layer boundary.
Implement: ITrustListResolver + a basic file/URL implementation; stub the LOTL hierarchy model.
Do NOT build 27-state aggregation or WRPAC handling (out of scope).
```

**`samples/Tessio.Sample.RelyingParty/CLAUDE.md`**
```
# Workstream E — Sample app, docs, conformance
Own samples/Tessio.Sample.RelyingParty, /docs, and the conformance harness.
Build: a runnable RP web app that starts in DEMO mode; a README quickstart (zero -> verified DEMO result in <=5 min);
a conformance harness targeting EUDI/OpenWallet test suites.
Start immediately against mocks; integrate as A-D land.
```

---

## 3. Merge in dependency order, then validate

Merge order follows the dependency graph:

```
D (Trust) + A (Core)  →  B (OpenId4Vp)  →  C (AspNetCore)  →  E (sample/docs)
```

After merging, on `main`, run the definition-of-done (brief §7): a green **DEMO-mode end-to-end** run through the sample app, plus the conformance harness.

---

## Notes

- **Contract change protocol:** if an agent needs a contract changed, it stops and flags it. You change it on `main`, re-tag, and have the other worktrees rebase. This single discipline is what keeps parallel agents from diverging.
- **Local secrets:** a worktree is a fresh checkout, so add a `.worktreeinclude` (gitignore syntax) at the repo root to copy `.env`-type files into each worktree.
- **Supervision:** treat the agents as junior-to-mid implementers. Review each package's tests before merging; the frozen contracts + per-package tests are your safety rail.
