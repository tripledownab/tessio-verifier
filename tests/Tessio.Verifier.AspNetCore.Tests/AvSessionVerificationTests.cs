using Microsoft.Extensions.DependencyInjection;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// A full EU Age Verification round trip: build the request with no request object, answer it with an
/// mdoc DeviceResponse, and verify that response against the session.
/// </summary>
/// <remarks>
/// <para>
/// This is the test the profile stands on. The device signature covers the session transcript, so it
/// passes only if the verifier recovered this request's response_uri, and it reports the right claim only
/// if it recovered the format and the docType. All four live in the query string, because the profile
/// sends no request object.
/// </para>
/// <para>
/// It also settles the transcript question the <c>redirect_uri</c> client identifier scheme raises: the
/// handover binds <c>client_id</c> verbatim, and under this profile that value is
/// <c>redirect_uri:&lt;response_uri&gt;</c> rather than a DNS or origin identifier.
/// </para>
/// </remarks>
public sealed class AvSessionVerificationTests : IDisposable
{
    private const string DocType = MockWalletResponses.EuAgeVerificationDocType;
    private static readonly Uri ResponseUri = new("https://verifier.example/wallet/callback");

    private readonly MockWalletResponses _wallet = new();

    private ServiceProvider BuildVerifier()
    {
        var services = new ServiceCollection();

        // Registered first so it wins over AddTessioVerifier's TryAddSingleton dev default. mdoc trust
        // anchors on the IACA root, not the SD-JWT issuer certificate.
        services.AddSingleton<ITrustListResolver>(
            _ => new StaticTrustListResolver([_wallet.MdocIssuerId], "test", [_wallet.MdocIacaCertificate]));

        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.CredentialFormat = "mso_mdoc";
            options.ExpectedDocType = DocType;
            options.MdocNamespace = DocType;
            options.RequestedClaims = ["age_over_18"];
            options.ResponseMode = ResponseMode.DirectPost;
        });

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// An AV session as a host holds one: the request built by <see cref="AvPresentationRequestBuilder"/>,
    /// carried in the frozen <see cref="PresentationRequest"/> shape whose <c>SignedRequestObject</c> is
    /// empty because this profile has none.
    /// </summary>
    private static async Task<VerificationSession> CreateAvSessionAsync()
    {
        var built = await new AvPresentationRequestBuilder(new AvPresentationRequestBuilderOptions())
            .BuildAsync(new PresentationRequestOptions
            {
                ClientId = $"redirect_uri:{ResponseUri}",
                Nonce = Guid.NewGuid().ToString("N"),
                State = Guid.NewGuid().ToString("N"),
                DcqlQueryJson = Dcql.Mdoc(DocType, DocType, "age_over_18"),
                ResponseUri = ResponseUri,
                ResponseMode = ResponseMode.DirectPost,
                ClientMetadataJson = null,
            });

        return new VerificationSession
        {
            SessionId = Guid.NewGuid().ToString("N"),
            Request = new PresentationRequest.ByValue
            {
                ClientId = built.ClientId,
                Nonce = built.Nonce,
                State = built.State,
                AuthorizationRequestUri = built.AuthorizationRequestUri,
                SignedRequestObject = "",
                ExpiresAt = built.ExpiresAt,
            },
            Status = VerificationSessionStatus.Pending,
            Result = null,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = built.ExpiresAt,
        };
    }

    [Fact]
    public async Task An_av_session_verifies_an_mdoc_response()
    {
        await using var provider = BuildVerifier();
        var session = await CreateAvSessionAsync();

        var response = _wallet.CreateMdocResponse(session, docType: DocType);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>().VerifyAsync(session, response);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[DocType]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Fact]
    public async Task An_av_session_reads_a_disclosed_no_as_a_no()
    {
        // A wallet holding age_over_18 = false answers with a flawless presentation carrying false. The
        // profile changes nothing about that: valid still does not mean old enough.
        await using var provider = BuildVerifier();
        var session = await CreateAvSessionAsync();

        var response = _wallet.CreateMdocResponse(
            session, docType: DocType, claimValues: new Dictionary<string, object> { ["age_over_18"] = false });
        var result = await provider.GetRequiredService<IWalletResponseVerifier>().VerifyAsync(session, response);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[DocType]);
        Assert.Equal(false, elements["age_over_18"]);
    }

    [Fact]
    public async Task An_av_session_rejects_a_response_for_a_different_docType()
    {
        // The docType is only enforceable because it was recovered from the query. Without it the mdoc
        // context carries no expectation and any document type verifies.
        await using var provider = BuildVerifier();
        var session = await CreateAvSessionAsync();

        var response = _wallet.CreateMdocResponse(session, docType: "org.iso.18013.5.1.mDL");
        var result = await provider.GetRequiredService<IWalletResponseVerifier>().VerifyAsync(session, response);

        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task An_av_session_rejects_a_response_that_answers_a_different_session()
    {
        // The device signature covers this session's client_id and nonce, so a replay must not verify.
        await using var provider = BuildVerifier();
        var session = await CreateAvSessionAsync();
        var other = await CreateAvSessionAsync();

        var response = _wallet.CreateMdocResponse(session, docType: DocType);
        var result = await provider.GetRequiredService<IWalletResponseVerifier>().VerifyAsync(other, response);

        Assert.False(result.IsValid);
    }

    public void Dispose() => _wallet.Dispose();
}
