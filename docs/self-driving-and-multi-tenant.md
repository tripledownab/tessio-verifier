# Self-driving and multi-tenant hosting

The batteries-included path in [going-live.md](going-live.md) mounts `/start` and `/callback` and drives a
single tenant from the process-wide `VerifierOptions`. This page is for the other shape: when you own the
session lifecycle (create and complete from your own API) or host many tenants in one process.
On that path you drive creation yourself, you correlate and complete the callback yourself and you verify
through a per-call seam instead of the built-in endpoint.

Reach for this when:

- you create verification sessions through your own typed API (with tenant or project context) rather than
  the library's `/start` endpoint
- you serve many tenants whose audience (`client_id`), credential type (`vct`) or document type differ
- you want your own storage, correlation and completion, and only need the library's verification core

## The moving parts

| Piece | Role |
|-------|------|
| `IStateCorrelatingSessionStore` | your durable store, indexed by OpenID4VP `state` |
| `IPresentationRequestBuilder` | builds the signed request (use the real signer for live wallets) |
| `IWalletResponseVerifier` | parses and verifies a wallet callback against one session |
| `Dcql` | builds the DCQL query for the request |
| `TessioVerifierSandbox` | optional demo completion when you have no wallet |
| `VerifierMode.Live` | registers no built-in completer, so your loop owns completion |

The verification seam is the key addition. `IWalletResponseVerifier` derives every expectation from the
session's own request (audience from `client_id`, nonce and the `vct` / `docType` from the request's DCQL),
so one process verifies any number of tenants without reading process-wide options.

## 1. Build the request

Build the `PresentationRequestOptions` yourself. `Dcql` produces the query so you never hand-write the JSON:

```csharp
using System.Security.Cryptography;
using Tessio.Verifier.OpenId4Vp;

var options = new PresentationRequestOptions
{
    ClientId = tenant.ClientId,                       // per tenant, e.g. x509_san_dns:tenant-a.example
    Nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
    State = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
    DcqlQueryJson = Dcql.AgeOver(18, tenant.Vct),     // or Dcql.SdJwtVc(vct, "given_name", "birth_date")
    ResponseUri = new Uri("https://verifier.example/v1/age-checks/callback"),
    ResponseMode = ResponseMode.DirectPost,           // start unencrypted; see the encryption note below
    RequestLifetime = TimeSpan.FromMinutes(5),
};

var request = await requestBuilder.BuildAsync(options, ct);
```

Persist the resulting session (see the next section) and render `request.AuthorizationRequestUri` as a QR
code or deep link. For by-reference delivery serve `request.SignedRequestObject` at the `request_uri`.

## 2. A durable session store

Behind a load balancer the callback can land on a different instance than the one that started the session,
so the store must be shared. Implement `IStateCorrelatingSessionStore` over Postgres, SQL Server, Redis or
any shared storage. The extra member beyond the base `ISessionStore` is `FindByStateAsync`: a wallet
response carries only `state`, so the callback path needs a state index.

```csharp
public sealed class PostgresSessionStore : IStateCorrelatingSessionStore
{
    // Table sessions(
    //   session_id   text primary key,
    //   state        text unique,          -- indexed: FindByStateAsync looks up by this
    //   status       int,
    //   request_json text,                 -- the whole PresentationRequest, incl. SignedRequestObject
    //   created_at   timestamptz,
    //   expires_at   timestamptz,
    //   result_json  text)

    public async Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default)
    {
        var request = await _requestBuilder.BuildAsync(options, ct);
        var session = new VerificationSession
        {
            SessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            Request = request,
            Status = VerificationSessionStatus.Pending,
            CreatedAt = _clock.GetUtcNow(),
            ExpiresAt = request.ExpiresAt,
        };
        // INSERT ... indexing request.State so FindByStateAsync can reach it.
        return session;
    }

    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) => /* SELECT by session_id */;
    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) => /* SELECT by state */;

    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) =>
        /* UPDATE status = Completed, result_json = ... WHERE session_id = ... AND status = Pending */;
}
```

Two things that cost real debugging time if you miss them:

- **Complete exactly once.** Make `CompleteAsync` a conditional update (`WHERE status = Pending`) and treat a
  second callback as a no-op or a conflict. Sessions complete once, which is also the replay guard.
- **Round-trip the timestamps as `DateTimeOffset`.** `CreatedAt` and `ExpiresAt` are `DateTimeOffset`. Npgsql
  maps `timestamptz` to `DateTime` by default, so map the columns back to `DateTimeOffset` explicitly (Dapper
  type handler or read the value and construct the offset) rather than letting a `DateTime` flow in.

## 3. Persist the whole request

The verifier recovers what the frozen request contract does not otherwise retain by reading the request
back:

- `response_uri`, for the mdoc device-authentication transcript
- `transaction_data`, which the wallet's Key Binding JWT must acknowledge
- the DCQL, from which the expected `vct`, `docType` and credential format are derived

A request carries those in one of two encodings, and the verifier reads either.

**JAR profiles (`SignedPresentationRequestBuilder`).** They live in the signed request object, so keep the
real `SignedRequestObject` on the `PresentationRequest`. Do not substitute an empty string. An empty value
only appears to work for an SD-JWT request that carries no transaction data. It breaks mdoc device
authentication and any transaction-data binding.

**The EU Age Verification profile (`AvPresentationRequestBuilder`).** It sends no request object at all, and
its parameters ride in the authorization request URI. Store `AuthorizationRequestUri` verbatim and set
`SignedRequestObject = ""`, which is the only value the frozen contract allows for "there is none".

Either way the `ClientId`, `Nonce` and `State` on `PresentationRequest` must round-trip too, since the seam
reads the audience and nonce from there.

Rows written before you persisted either encoding have neither, and a response cannot be checked against
them. Call `WalletResponseVerifier.CanVerify(session.Request)` and refuse those, rather than verifying
against a request that says nothing:

```csharp
if (!WalletResponseVerifier.CanVerify(session.Request))
{
    return Results.Conflict(new { error = "check_not_verifiable" });
}
```

## 4. Verify the callback

Correlate the response to a session by `state`, then verify. `IWalletResponseVerifier` parses the raw
response (picking SD-JWT or mdoc from the session's request) and returns a `VerificationResult`. A malformed
or undecryptable response comes back as an invalid result rather than an exception, so the verify-then-
complete line never has to catch:

```csharp
app.MapPost("/v1/age-checks/callback",
    async (HttpContext http, IWalletResponseVerifier verifier, PostgresSessionStore store, CancellationToken ct) =>
{
    var form = await http.Request.ReadFormAsync(ct);
    var response = new WalletResponseData
    {
        ContentType = http.Request.ContentType ?? "application/x-www-form-urlencoded",
        Form = form.ToDictionary(f => f.Key, f => (IReadOnlyList<string>)f.Value.ToArray(), StringComparer.Ordinal),
        Body = ReadOnlyMemory<byte>.Empty,
    };

    // WalletResponseData carries no State property. For cleartext direct_post the state is a form field.
    var state = form.TryGetValue("state", out var values) ? values.ToString() : null;
    if (state is null) return Results.BadRequest();

    var session = await store.FindByStateAsync(state, ct);
    if (session is null) return Results.NotFound();
    if (session.Status != VerificationSessionStatus.Pending) return Results.Conflict();

    var result = await verifier.VerifyAsync(session, response, ct);
    await store.CompleteAsync(session.SessionId, result, ct);
    return Results.Ok();
});
```

For encrypted `direct_post.jwt` responses the `state` travels inside the encrypted JWT, so it is not a form
field. Extract it with the public parser once the response key is available:
`(await new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKey = key }).ParseDetailedAsync(response, ct)).State`.

## 5. Multi-tenant correctness

Because the seam reads audience, nonce, `vct`, `docType`, format and response mode from each session's own
request, nothing is process-wide. Give every tenant its own `client_id` and DCQL at create time and the same
process verifies them all, including a mix of SD-JWT and mdoc tenants. There is no per-request option to set
at the call site and nothing to keep in sync.

Response encryption is per session too. `ResponseEncryptionKeyStore.CreateForRequest` mints a key for each
authorization request, the request advertises it in `client_metadata`, and the callback resolves it again by
the `kid` the wallet echoes. Two tenants, and two in-flight requests of one tenant, each get their own key.

The keys are held in memory, so a callback must reach the instance that issued the request. On more than one
instance, wire a shared key source: see [going-live.md](going-live.md) section 6, which recommends deriving
each request's key from one KMS master secret and storing only a per-request salt.

## 6. Completing sessions without a wallet

For demos, samples and tests where you create sessions yourself, `TessioVerifierSandbox` completes a session
with a synthesized valid result:

```csharp
await sandbox.CompleteWithDemoResultAsync(session.SessionId, ct);
```

This is demo and test only: the result is synthesized from the configured requested claims, not verified
against a real credential. It completes immediately and works in any mode, unlike the built-in `Demo`
completer, which only auto-completes sessions created through `/start`.

## 7. Mode and trust

Run `VerifierMode.Live` for real wallets: it registers no built-in completer, so your loop owns completion.
Live also requires a real signed request builder and a real trust list. See [going-live.md](going-live.md)
for that setup.
