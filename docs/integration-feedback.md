# Integration feedback — hosting the verifier multi-tenant

Feedback from building **Tessio.Cloud** on top of `Tessio.Verifier` — a hosted, multi-tenant EUDI
age-verification API where the customer calls `POST /v1/age-checks` and polls `GET /v1/age-checks/{id}`.
We consumed the library via NuGet `Tessio.Verifier.AspNetCore` **0.2.1** and drove the flow ourselves: our
own `IStateCorrelatingSessionStore` (Postgres), our own create + completion, **bypassing the built-in
`/start` and `/callback` endpoints**. That "self-driving host" path is where most of the friction below
lives — the batteries-included single-tenant path (`going-live.md`) is smooth.

Everything is cited to `file:line` in `src/` and comes from real integration.

> **Revised after maintainer review.** The original draft was written without visibility into the
> **`contracts-v0` freeze**, which reshapes how two of the fixes should land. This revision incorporates
> that constraint, the maintainer's added facts on #1 and #5, and the re-prioritisation.

## Constraint: `contracts-v0` is FROZEN — do not modify

Six referenced types are marked **FROZEN contract**; changes to them must be **additive or documentation only**,
never breaking:

`ISessionStore` · `PresentationRequest` · `VerificationResult` · `IssuerInfo` · `VerificationContext` · `VerificationSession`

The freeze doesn't block anything below — but it means **#3** and **#5** as originally proposed were breaking, and
are re-cast as *docs* / *leave-as-is*. Each finding is tagged with how its fix should land:

- **additive** — new public API alongside the frozen types (safe)
- **docs** — no code change; document the correct usage
- **low** — accept as-is; cost of the friction is tiny

| # | Finding | Impact | Landing | Touches frozen |
|---|---------|--------|---------|----------------|
| 1 | Multi-tenant callback path isn't reachable **and** binds the wrong audience | 🔴 blocker + latent bug | additive (new seam, context-from-session) | reads them, modifies none |
| 6 | Verbose result synthesis | 🟢 quick win | additive (`Valid/Invalid` factories) | `VerificationResult`,`IssuerInfo` |
| 4 | `DemoRequestOptionsFactory` is `internal` | 🟠 | additive (public DCQL helper) | no |
| 2 | Demo/Mock completion coupled to `/start` (silent no-op) | 🟠 | additive (public enqueue) **or** docs | no |
| 5 | `SignedRequestObject` required + the `""` shortcut is format-dependent | 🟠 | **docs** (correctness note) | `PresentationRequest` |
| 7 | Only an in-memory store example | 🟡 | docs | no |
| 8 | Self-driving / multi-tenant framing missing | 🟡 | docs | no |
| 3 | `ISessionStore.CreateAsync` forced on self-driving hosts | 🔵 low | leave as-is (split would be breaking) | `ISessionStore` |
| 9 | `net8;net10` packaging | ⚪ non-issue | skip | no |

---

## 🔴 The real blocker

### 1. Multi-tenant Live verify isn't reachable — and the reachable orchestration binds the wrong audience

*Landing: **additive**. Reads frozen types, modifies none.*

`WalletCallbackProcessor` is `internal sealed` (`src/Tessio.Verifier.AspNetCore/WalletCallbackProcessor.cs:24`)
and binds the **singleton** `VerifierOptions` (`_options = options.Value`, `:54`). The verification context is
built entirely from those app-wide options, not from the session:

- SD-JWT: `Audience = _options.ClientId`, `ExpectedVct = _options.ExpectedVct ?? …` (`:102-103`)
- mdoc: `_options.ExpectedDocType` / `_options.ResponseMode` (`:140-143`)

It's worse than "the processor is internal" — **the parse step is single-tenant too**: `WalletResponseParser`
is registered as a singleton with `PresentationFormat = options.Value.CredentialFormat`
(`TessioVerifierServiceCollectionExtensions.cs:57`). So format is pinned per process as well.

**This is a latent correctness issue, not just an unreachable feature.** Using `_options.ClientId` as the
SD-JWT audience instead of `session.Request.ClientId` means that in *any* multi-tenant process the audience
check runs against the app-wide client id, not the one the request was actually issued under. The session
already carries `ClientId` and `Nonce`, and the signed request already carries the `vct` in its DCQL — so the
information to verify correctly is present per-session; only the orchestration ignores it.

The building blocks are already public and per-call stateless:

- `SdJwtVcVerifier.VerifyAsync(...)` — `src/Tessio.Verifier.Core/SdJwtVcVerifier.cs:61`
- `MdocVerifier.VerifyAsync(...)` — `src/Tessio.Verifier.Core.Mdoc/MdocVerifier.cs:45`
- `WalletResponseParser` — `src/Tessio.Verifier.AspNetCore/WalletResponseParser.cs:14`

**Suggested direction (a design decision worth making explicitly):** rather than "pass options explicitly,"
the cleaner seam **derives the `VerificationContext` from the session/request** — audience from
`session.Request.ClientId`, nonce from `session.Request.Nonce`, `vct`/format from the request's DCQL — with
the singleton options as fallback only. Expose that as a public per-call verification service (additive; the
frozen types are inputs/outputs, not modified). This fixes the multi-tenant *and* the latent-audience bug in
one move.

---

## 🟢 Quick win

### 6. `required` members make synthesizing a `VerificationResult` verbose

*Landing: **additive** — the cleanest, lowest-risk win.*

To hand `CompleteAsync` a "valid" result (sandbox completion, and every test) we populate
`VerificationResult { IsValid, DisclosedClaims, Issuer, Errors }` (4 required, `VerificationResult.cs:10-22`)
**and** nested `IssuerInfo { Identifier, Trusted, KeyResolutionMethod }` (3 required). Both are FROZEN, but
**static factories are purely additive**. Private equivalents already exist internally
(`SdJwtVcVerifier.Invalid`, `MdocVerifier.Failure`), so promoting a public
`VerificationResult.Valid(claims, issuer)` / `VerificationResult.Invalid(errors)` is low-risk and helps
driver code and tests alike.

---

## 🟠 Additive helpers

### 4. `DemoRequestOptionsFactory` is `internal`

*Landing: **additive**.*

`src/Tessio.Verifier.AspNetCore/DemoRequestOptionsFactory.cs:10` (`internal static`). No public DCQL helper
exists anywhere, so building even a standard request means hand-writing DCQL JSON (we wrote our own
`Dcql.ForAgeOver(n)`), and getting the shape subtly wrong only surfaces at the wallet. A public helper for the
common cases (single-claim SD-JWT VC by `vct`, `age_over_N`) centralises the query shape the library already
knows.

### 2. Demo/Mock auto-completion is silently coupled to the built-in `/start` endpoint

*Landing: **additive** (public enqueue) **or docs**.*

Enqueue happens **only** inside `StartAsync`
(`src/Tessio.Verifier.AspNetCore/TessioVerifierEndpointRouteBuilderExtensions.cs:90-99`), and the completer
hosted services register only for their mode (`TessioVerifierServiceCollectionExtensions.cs:80-88`). Bypass
`/start` and nothing fires — silently; pending checks just sit there. The mode names reinforce the wrong model
("Demo" reads as *build without wallets*, but it only works through the library's own endpoint). We ended up
on `VerifierMode.Live` (no completer) plus our own background completer.

Note this is genuinely additive work, not an access-modifier flip: `DemoCompletionQueue` is `internal sealed`
(`DemoCompletionQueue.cs:9`). The cheap alternative is a one-line XML-doc note on `VerifierMode.Demo` —
*"only auto-completes sessions created via the built-in `/start` endpoint"* — which would have saved the
debugging on its own.

---

## 🟡 Documentation

### 5. `SignedRequestObject` is `required`, and the `""` shortcut is format-dependent

*Landing: **docs**. `PresentationRequest` is FROZEN (`:6-10`) — do **not** make the field nullable.*

`src/Tessio.Verifier.OpenId4Vp/PresentationRequest.cs:44` (`public required string`). Reconstructing a
`VerificationSession` for the callback path, we set `SignedRequestObject = ""` and SD-JWT verification worked —
**but the original "`""` works" claim was too broad.** `""` is safe only for **SD-JWT without
`transaction_data`**:

- `TryGetTransactionData("")` and `TryGetResponseUri("")` both return null (splitting on `.` yields length 1).
- For **mdoc**, that null `ResponseUri` makes `VerifyDeviceAuth` fail with `DeviceAuthInvalid`
  (`MdocVerifier.cs:174-182`).
- For **SD-JWT with `transaction_data`**, the KB-JWT hash binding can't be checked.

**Correct guidance (docs, not a nullability change):** a store must reconstruct the session with the **real**
request object — you need it for mdoc and for transaction data. The field is only effectively "optional" in the
narrow SD-JWT-without-transaction-data case, and that caveat should be documented rather than encoded as a
nullable field.

### 7. The only session-store example is in-memory

*Landing: **docs**.*

The single worked store is `DictionarySessionStore` in the tests; `going-live.md` §5 shows only the interface
signature. A durable reference (Postgres/Dapper or EF) would have saved most of our integration time — it
should show the **`state` index** the callback path requires (the `WalletCallbackProcessor` ctor throws a great
error pointing at `IStateCorrelatingSessionStore`, but there's no example of *satisfying* it durably) and the
**`DateTimeOffset` ↔ DB timestamp** round-trip (the model uses `DateTimeOffset`; Npgsql maps `timestamptz` →
`DateTime`, and the mismatch cost us a materialisation debugging cycle).

### 8. The self-driving / multi-tenant framing is missing

*Landing: **docs**. (Original draft overstated this.)*

`going-live.md` §5 **does** document the `IStateCorrelatingSessionStore` seam and the create/complete
responsibilities — so "only discoverable from source" was wrong. What's genuinely missing is the *self-driving*
framing (drive create + completion yourself, bypass `/start`, run Live with your own completer) and the
multi-tenant story (#1). A short companion page to `going-live.md` covering that would close the gap.

---

## 🔵 Low priority / non-issues

### 3. `ISessionStore.CreateAsync` is forced on self-driving hosts — but leave it

*Landing: **low / leave as-is**.*

The interface is Create + Get + Complete, all required (`ISessionStore.cs:13-24`), and it is **FROZEN**
(`:10`). Splitting it into reader/completer/creator would modify a frozen contract (breaking); additive
alternatives exist but are messier than the problem. The practical cost is a one-line
`throw new NotSupportedException` in the self-driving `CreateAsync`. **Downgraded** from the original "medium" —
not worth churning the contract.

### 9. `net8;net10` packaging — effectively a non-issue

`TargetFrameworks = net8.0;net10.0` (`Tessio.Verifier.AspNetCore.csproj:4`). NuGet resolves a **net9** consumer
to the `net8.0` asset automatically (nearest-compatible), with no fallback warning — so the "tidier restore"
already happens. Skip unless a `net9.0` TFM is specifically wanted for AOT/trimming.

---

## 👍 What worked well (keep it)

- **The store-contract error message.** When the registered `ISessionStore` isn't
  `IStateCorrelatingSessionStore`, the callback processor throws a message that names the exact interface to
  implement and *why* (`WalletCallbackProcessor.cs:48-53`). That single message told us precisely what to do.
- **Public, stateless `VerifyAsync`.** `SdJwtVcVerifier` / `MdocVerifier` / `WalletResponseParser` exposing
  their work as pure, per-call functions is exactly what makes fix #1 tractable without touching frozen types.
- **`AddTessioVerifier` uses `TryAdd`**, so registering our `ISessionStore` (and other seams) *before* it
  cleanly wins — a clean extension point, well documented in `going-live.md`.

---

*Authored from the Tessio.Cloud integration (`a consuming application`,
`the consuming project`), revised after maintainer review. Happy to turn #1, #6, #4 and #2 into
issues/PRs (all additive) against this repo.*
