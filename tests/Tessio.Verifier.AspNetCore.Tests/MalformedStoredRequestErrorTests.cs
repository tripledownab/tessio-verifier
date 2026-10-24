using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// A wallet's decline is its answer, whatever shape the stored request is in. A host's own session store can hand
/// back a request these readers cannot take (a non-string <c>kid</c>, a <c>client_metadata</c> that is not an object),
/// and verifying the decline must not read it: the request is consulted only for a presentation, and only for the
/// parameters that presentation's format needs.
/// </summary>
public sealed class MalformedStoredRequestErrorTests
{
    private static VerificationSession SessionWithRequestPayload(string payloadJson)
    {
        var requestObject = $"{Base64UrlEncoder.Encode("""{"alg":"none"}""")}.{Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payloadJson))}.";
        return new VerificationSession
        {
            SessionId = "session-1",
            Status = VerificationSessionStatus.Pending,
            CreatedAt = DateTimeOffset.UnixEpoch,
            ExpiresAt = DateTimeOffset.MaxValue,
            Request = new PresentationRequest.ByValue
            {
                ClientId = "x509_san_dns:verifier.example",
                Nonce = "nonce-1",
                AuthorizationRequestUri = new Uri("openid4vp://authorize"),
                SignedRequestObject = requestObject,
                ExpiresAt = DateTimeOffset.MaxValue,
            },
        };
    }

    private static readonly WalletResponseData Decline = new()
    {
        ContentType = "application/x-www-form-urlencoded",
        Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["error"] = ["access_denied"],
            ["state"] = ["state-1"],
        },
        Body = ReadOnlyMemory<byte>.Empty,
    };

    [Theory]
    [InlineData("""{"response_mode":"direct_post.jwt","client_metadata":{"jwks":{"keys":[{"kid":42}]}},"dcql_query":{"credentials":[{"format":"mso_mdoc","meta":{"doctype_value":"x"}}]}}""")]
    [InlineData("""{"response_mode":"direct_post.jwt","client_metadata":{"jwks":{"keys":[{"kid":"a"}]}},"dcql_query":{"credentials":[{"format":"mso_mdoc","meta":{"doctype_value":"x"}}]}}""")]
    [InlineData("""{"response_mode":"direct_post.jwt","client_metadata":"not an object","dcql_query":{"credentials":[{"format":"mso_mdoc","meta":{"doctype_value":"x"}}]}}""")]
    [InlineData("""{"response_mode":"direct_post","dcql_query":{"credentials":[{"format":"dc+sd-jwt","meta":"not an object"}]}}""")]
    public async Task ADecline_IsAWalletError_WhateverTheStoredRequestHolds(string payloadJson)
    {
        var services = new ServiceCollection();
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
        await using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IWalletResponseVerifier>()
            .VerifyAsync(SessionWithRequestPayload(payloadJson), Decline);

        Assert.Equal(ErrorCodes.WalletError, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task AnAlreadyParsedDecline_IsAWalletError_EvenWhenTheStoreLostTheRequest()
    {
        // The built-in callback parses first and hands the decline to VerifyParsedAsync. Request is required, but a
        // host's store can deserialize past that, and the decline needs nothing from it.
        var services = new ServiceCollection();
        services.AddTessioVerifier(options => options.Mode = VerifierMode.Mock);
        await using var provider = services.BuildServiceProvider();
        var session = SessionWithRequestPayload("{}") with { Request = null! };
        var decline = new ParsedWalletResponse { Credentials = [], Error = "access_denied" };

        var result = await provider.GetRequiredService<WalletResponseVerifier>()
            .VerifyParsedAsync(session, decline, CancellationToken.None);

        Assert.Equal(ErrorCodes.WalletError, Assert.Single(result.Errors).Code);
    }
}
