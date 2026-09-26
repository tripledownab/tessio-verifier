using Microsoft.Extensions.DependencyInjection;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Proves the public multi-tenant seam: <see cref="IWalletResponseVerifier"/> parses and verifies a raw
/// wallet response using expectations from the session's own request (audience, nonce, vct, format), so one
/// process verifies callbacks for many tenants without the app-wide <see cref="VerifierOptions"/>, and
/// <see cref="TessioVerifierSandbox"/> completes a self-created session without the built-in <c>/start</c>.
/// </summary>
public sealed class MultiTenantVerificationTests
{
    private const string TenantA = "x509_san_dns:tenant-a.example";
    private const string TenantAVct = "https://tenant-a.example/vct/identity";
    private const string TenantB = "x509_san_dns:tenant-b.example";
    private const string TenantBVct = "https://tenant-b.example/vct/identity";

    private static ServiceProvider BuildProvider(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection()
            .AddTessioVerifier(options =>
            {
                options.Mode = VerifierMode.Mock;
                // Deliberately not any tenant's client_id: the seam must ignore this and use the session's.
                options.ClientId = "process-wide-verifier";
                options.RequestedClaims = ["age_over_18"];
            });

        // Registered after AddTessioVerifier so a test can substitute one of its services.
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// A session whose DCQL entry offers SEVERAL credential types, the shape a self-driving host builds
    /// for itself. <c>DemoRequestOptionsFactory</c> asks for one type only, so the options are assembled
    /// here, but the query still comes from <see cref="Dcql"/>: it is the one builder for that object,
    /// and a query written out by hand in a test is free to drift from the one production sends.
    /// </summary>
    private static async Task<VerificationSession> CreateMultiVctSessionAsync(
        ServiceProvider provider, string clientId, params string[] vctValues) =>
        await provider.GetRequiredService<InMemorySessionStore>().CreateAsync(new PresentationRequestOptions
        {
            ClientId = clientId,
            Nonce = Tokens.NewNonce(),
            State = Tokens.NewNonce(),
            DcqlQueryJson = Dcql.SdJwtVc(vctValues, "age_over_18"),
            ResponseUri = new Uri("https://verifier.example/verify/callback"),
            ResponseMode = ResponseMode.DirectPost,
            RequestLifetime = TimeSpan.FromMinutes(5),
        });

    private static async Task<VerificationSession> CreateTenantSessionAsync(
        ServiceProvider provider, string clientId, string vct)
    {
        var store = provider.GetRequiredService<InMemorySessionStore>();
        var tenantOptions = new VerifierOptions { ClientId = clientId, ExpectedVct = vct, RequestedClaims = ["age_over_18"] };
        return await store.CreateAsync(DemoRequestOptionsFactory.Create(
            tenantOptions, new Uri("https://verifier.example/verify/callback")));
    }

    // A cleartext direct_post wallet POST carrying one presentation, as the parser expects.
    private static WalletResponseData ResponseWith(VerificationSession session, string vpTokenJson) => new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["vp_token"] = new[] { vpTokenJson },
            ["state"] = new[] { session.Request.State! },
        },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    private static WalletResponseData ResponseFor(VerificationSession session, string presentation) =>
        ResponseWith(session, $$"""{"credential":["{{presentation}}"]}""");

    private static async Task<VerificationSession> CreateEncryptedSessionAsync(
        ServiceProvider provider, string clientId, string vct)
    {
        var store = provider.GetRequiredService<InMemorySessionStore>();

        // A fresh per-request key from the store, so client_metadata advertises it and the callback can
        // find it again by kid, exactly as MapTessioVerifier's /start does.
        var encryptionJwk = provider.GetRequiredService<ResponseEncryptionKeyStore>()
            .CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk;

        var tenantOptions = new VerifierOptions
        {
            ClientId = clientId,
            ExpectedVct = vct,
            RequestedClaims = ["age_over_18"],
            ResponseMode = ResponseMode.DirectPostJwt,
        };
        return await store.CreateAsync(DemoRequestOptionsFactory.Create(
            tenantOptions, new Uri("https://verifier.example/verify/callback"), encryptionJwk));
    }

    // An ENCRYPTED direct_post.jwt wallet POST: a single "response" JWE encrypted to the key the session
    // advertised, produced by the same encryptor a real wallet uses. This is the path a self-driving host
    // takes on the HAIP default response mode, and the only one that exercises the verifier's own key
    // resolver.
    private static WalletResponseData EncryptedResponseFor(VerificationSession session, string presentation)
    {
        var recipientJwkJson = RequestParameters.TryGetEncryptionJwkJson(session.Request)!;
        var payload = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = new Dictionary<string, string[]> { ["credential"] = [presentation] },
            ["state"] = session.Request.State!,
        });

        return new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["response"] = new[] { EcdhEsJweEncryptor.Encrypt(payload, recipientJwkJson) },
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
    }

    [Fact]
    public async Task Verify_DecryptsEncryptedResponse_WithThisSessionsEphemeralKey()
    {
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        // Two independent sessions, each advertising its OWN key. If the verifier resolved a single
        // shared key, one of these would decrypt against the wrong one and fail; keyed by kid, both pass.
        var sessionA = await CreateEncryptedSessionAsync(provider, TenantA, TenantAVct);
        var sessionB = await CreateEncryptedSessionAsync(provider, TenantB, TenantBVct);

        var presentationA = issuer.IssuePresentation(["age_over_18"], TenantAVct, sessionA.Request.Nonce, TenantA);
        var presentationB = issuer.IssuePresentation(["age_over_18"], TenantBVct, sessionB.Request.Nonce, TenantB);

        var resultA = await verifier.VerifyAsync(sessionA, EncryptedResponseFor(sessionA, presentationA));
        var resultB = await verifier.VerifyAsync(sessionB, EncryptedResponseFor(sessionB, presentationB));

        Assert.True(resultA.IsValid, string.Join("; ", resultA.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.True(resultB.IsValid, string.Join("; ", resultB.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task Verify_DerivesAudienceAndVctFromSession_NotProcessWideOptions()
    {
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        var session = await CreateTenantSessionAsync(provider, TenantA, TenantAVct);

        // A wallet answering tenant A: KB-JWT bound to tenant A's client_id, credential of tenant A's vct.
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], TenantAVct, session.Request.Nonce, TenantA);

        var result = await verifier.VerifyAsync(session, ResponseFor(session, presentation));

        // Passes even though the process-wide client_id is "process-wide-verifier": audience came from the
        // session's request, and the expected vct from that request's DCQL.
        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.Equal(true, result.DisclosedClaims["age_over_18"]);
    }

    [Fact]
    public async Task Verify_TwoTenantsInOneProcess_EachAgainstItsOwnRequest()
    {
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        var sessionA = await CreateTenantSessionAsync(provider, TenantA, TenantAVct);
        var sessionB = await CreateTenantSessionAsync(provider, TenantB, TenantBVct);

        var presentationA = issuer.IssuePresentation(["age_over_18"], TenantAVct, sessionA.Request.Nonce, TenantA);
        var presentationB = issuer.IssuePresentation(["age_over_18"], TenantBVct, sessionB.Request.Nonce, TenantB);

        Assert.True((await verifier.VerifyAsync(sessionA, ResponseFor(sessionA, presentationA))).IsValid);
        Assert.True((await verifier.VerifyAsync(sessionB, ResponseFor(sessionB, presentationB))).IsValid);

        // Tenant A's presentation cannot be verified against tenant B's session.
        Assert.False((await verifier.VerifyAsync(sessionB, ResponseFor(sessionB, presentationA))).IsValid);
    }

    [Fact]
    public async Task Verify_FailsWhenPresentationAudienceIsNotTheSessionClientId()
    {
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        var session = await CreateTenantSessionAsync(provider, TenantA, TenantAVct);

        // Correct nonce and vct, but bound to a different verifier's audience.
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], TenantAVct, session.Request.Nonce, TenantB);

        var result = await verifier.VerifyAsync(session, ResponseFor(session, presentation));

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task Verify_FailsWhenPresentationVctDoesNotMatchTheRequest()
    {
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        var session = await CreateTenantSessionAsync(provider, TenantA, TenantAVct);

        var presentation = issuer.IssuePresentation(
            ["age_over_18"], "https://wrong.example/vct", session.Request.Nonce, TenantA);

        var result = await verifier.VerifyAsync(session, ResponseFor(session, presentation));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "vct_mismatch");
    }

    [Fact]
    public async Task Verify_AcceptsAnyVctTheRequestOffered_NotOnlyTheFirst()
    {
        // The whole chain in one pass: RequestParameters reads vct_values back out of the session's own
        // request, WalletResponseVerifier puts the set on the context, and SdJwtVcVerifier checks
        // membership. SPEC: OpenID4VP 1.0 §8.6 requires the Verifier to "validate that the returned
        // Credential(s) meet all criteria defined in the query", and §B.3.5 states that criterion as a
        // non-empty array of ALLOWED values. The credential is of the SECOND value, so reverting any
        // link in that chain to vct_values[0] turns this red.
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        var session = await CreateMultiVctSessionAsync(provider, TenantA, TenantAVct, TenantBVct);
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], TenantBVct, session.Request.Nonce, TenantA);

        var result = await verifier.VerifyAsync(session, ResponseFor(session, presentation));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task Verify_StillGivesACustomCredentialVerifierTheExpectedVct()
    {
        // WalletResponseVerifier hands the context to whatever ICredentialVerifier the host registered,
        // and the built-in one now reads ExpectedVctValues. A host implementing the interface against
        // ExpectedVct alone must keep receiving a type to compare: reading null there would skip its
        // check silently, which is a downgrade rather than a failure. Both properties are set, so the
        // older one narrows rather than disappears.
        var capturing = new CapturingCredentialVerifier();
        await using var provider = BuildProvider(services => services.AddSingleton<ICredentialVerifier>(capturing));
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var issuer = provider.GetRequiredService<MockCredentialIssuer>();

        var session = await CreateMultiVctSessionAsync(provider, TenantA, TenantAVct, TenantBVct);
        var presentation = issuer.IssuePresentation(
            ["age_over_18"], TenantBVct, session.Request.Nonce, TenantA);

        await verifier.VerifyAsync(session, ResponseFor(session, presentation));

        var seen = Assert.IsType<VerificationContext>(capturing.Seen);
        Assert.Equal(TenantAVct, seen.ExpectedVct);
        Assert.Equal(new[] { TenantAVct, TenantBVct }, seen.ExpectedVctValues);
    }

    /// <summary>Records the context it is given and verifies nothing.</summary>
    private sealed class CapturingCredentialVerifier : ICredentialVerifier
    {
        public VerificationContext? Seen { get; private set; }

        public Task<VerificationResult> VerifyAsync(
            PresentedCredential credential, VerificationContext context, CancellationToken ct = default)
        {
            Seen = context;
            return Task.FromResult(VerificationResult.Invalid(
                new VerificationError { Code = "captured", Message = "This verifier only records." }));
        }
    }

    [Fact]
    public async Task Verify_MalformedResponse_ReturnsInvalidResultRatherThanThrowing()
    {
        await using var provider = BuildProvider();
        var verifier = provider.GetRequiredService<IWalletResponseVerifier>();
        var session = await CreateTenantSessionAsync(provider, TenantA, TenantAVct);

        // Empty vp_token object: the parser rejects it. The seam surfaces that as an invalid result so the
        // caller's one-liner (verify -> complete) never has to catch.
        var result = await verifier.VerifyAsync(session, ResponseWith(session, "{}"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "response_invalid");
    }

    [Fact]
    public async Task Sandbox_CompletesSelfCreatedSession_WithSynthesizedResult()
    {
        await using var provider = BuildProvider();
        var sandbox = provider.GetRequiredService<TessioVerifierSandbox>();
        var store = provider.GetRequiredService<InMemorySessionStore>();
        var session = await CreateTenantSessionAsync(provider, TenantA, TenantAVct);

        Assert.Equal(VerificationSessionStatus.Pending, session.Status);

        await sandbox.CompleteWithDemoResultAsync(session.SessionId);

        var terminal = await store.GetAsync(session.SessionId);
        Assert.Equal(VerificationSessionStatus.Completed, terminal!.Status);
        Assert.True(terminal.Result!.IsValid);
        Assert.Equal(true, terminal.Result.DisclosedClaims["age_over_18"]);
    }
}
