using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// A request delivers its parameters in one of two encodings, and verification reads either. The JAR
/// profiles carry them as claims in the signed request object; the EU Age Verification profile has no
/// request object and carries them as plain query parameters.
/// </summary>
/// <remarks>
/// Reading only the JAR left every AV expectation null: the credential format fell back to SD-JWT VC and
/// the docType went unchecked, so an mdoc age attestation could not be verified against what was asked
/// for.
/// </remarks>
public sealed class RequestParametersTests
{
    private const string DocType = "eu.europa.ec.av.1";
    private static readonly Uri ResponseUri = new("https://verifier.example/wallet/callback");

    private static async Task<PresentationRequest> BuildAvRequestAsync()
    {
        var built = await new AvPresentationRequestBuilder(new AvPresentationRequestBuilderOptions())
            .BuildAsync(new PresentationRequestOptions
            {
                ClientId = $"redirect_uri:{ResponseUri}",
                Nonce = "nonce-1",
                State = "state-1",
                DcqlQueryJson = Dcql.Mdoc(DocType, DocType, "age_over_18"),
                ResponseUri = ResponseUri,
                ResponseMode = ResponseMode.DirectPost,
                ClientMetadataJson = null,
            });

        return AsSessionRequest(built.AuthorizationRequestUri, requestObject: "", built);
    }

    /// <summary>
    /// What a host does when it persists an AV session: the frozen <see cref="PresentationRequest"/>
    /// contract requires a <c>SignedRequestObject</c>, and this profile has none, so the empty string
    /// stands for its absence and the parameters are read from the URI instead.
    /// </summary>
    private static PresentationRequest.ByValue AsSessionRequest(
        Uri authorizationRequestUri, string requestObject, AvPresentationRequest? built = null) =>
        new()
        {
            ClientId = built?.ClientId ?? "client",
            Nonce = built?.Nonce ?? "nonce-1",
            State = built?.State ?? "state-1",
            AuthorizationRequestUri = authorizationRequestUri,
            SignedRequestObject = requestObject,
            ExpiresAt = built?.ExpiresAt ?? DateTimeOffset.UtcNow.AddMinutes(5),
        };

    [Fact]
    public async Task Av_request_carries_its_parameters_in_the_query()
    {
        var request = await BuildAvRequestAsync();

        Assert.Equal("mso_mdoc", RequestParameters.TryGetRequestedFormat(request));
        Assert.Equal(DocType, RequestParameters.TryGetExpectedDocType(request));
        Assert.Equal(ResponseUri.ToString(), RequestParameters.TryGetResponseUri(request));
        Assert.Equal("direct_post", RequestParameters.TryGetResponseMode(request));
    }

    [Fact]
    public async Task Av_request_advertises_no_encryption_key_and_no_transaction_data()
    {
        // Not an artefact of reading the wrong place: the profile has neither. direct_post is cleartext,
        // and client_metadata is absent from the request altogether.
        var request = await BuildAvRequestAsync();

        Assert.Null(RequestParameters.TryGetEncryptionJwkJson(request));
        Assert.Null(RequestParameters.TryGetEncryptionKeyThumbprint(request));
        Assert.Null(RequestParameters.TryGetTransactionData(request));
    }

    [Fact]
    public async Task Av_request_is_verifiable()
    {
        Assert.True(WalletResponseVerifier.CanVerify(await BuildAvRequestAsync()));
    }

    [Fact]
    public void A_request_with_neither_encoding_is_not_verifiable()
    {
        // The row a host wrote before it persisted enough to verify against: no request object, and an
        // authorization URI that carries no DCQL. Nothing a wallet returns can be checked against it.
        var request = AsSessionRequest(new Uri("https://verifier.example/start?session=1"), requestObject: "");

        Assert.False(WalletResponseVerifier.CanVerify(request));
        Assert.Null(RequestParameters.TryGetRequestedFormat(request));
        Assert.Null(RequestParameters.TryGetResponseUri(request));
    }

    [Fact]
    public void A_query_that_is_not_the_request_does_not_masquerade_as_one()
    {
        // A URI with a query string but no dcql_query is not a request. Reading it parameter by parameter
        // would report a response_uri for a session that never asked for anything.
        var request = AsSessionRequest(
            new Uri($"https://verifier.example/start?response_uri={Uri.EscapeDataString(ResponseUri.ToString())}"),
            requestObject: "");

        Assert.False(WalletResponseVerifier.CanVerify(request));
        Assert.Null(RequestParameters.TryGetResponseUri(request));
    }

    [Fact]
    public async Task A_query_carrying_transaction_data_is_refused_rather_than_guessed_at()
    {
        // SPEC: OpenID4VP 1.0 §5.1 defines transaction_data as a "Non-empty array of strings", so the
        // rule that "parameters containing objects are transferred as JSON-serialized strings" does not
        // settle how it appears in a query. Reading it wrong would silently drop a binding the wallet's
        // Key Binding JWT has to acknowledge, so the request reads as unrecoverable until that is
        // settled by a builder that actually needs to send one.
        var av = await BuildAvRequestAsync();
        var withTd = new Uri($"{av.AuthorizationRequestUri.AbsoluteUri}&transaction_data=%5B%22abc%22%5D");

        Assert.False(WalletResponseVerifier.CanVerify(AsSessionRequest(withTd, requestObject: "")));
    }

    [Fact]
    public async Task The_signed_request_object_wins_over_the_query_string()
    {
        // Both encodings present and disagreeing. The signed copy is the one whose integrity is protected,
        // so it decides; otherwise an attacker who could rewrite the URI could rewrite the expectations.
        var av = await BuildAvRequestAsync();
        var jar = UnsignedRequestObject("""
            {"response_uri":"https://signed.example/callback","response_mode":"direct_post.jwt",
             "dcql_query":{"credentials":[{"id":"credential","format":"dc+sd-jwt",
             "meta":{"vct_values":["https://signed.example/vct"]}}]}}
            """);

        var request = AsSessionRequest(av.AuthorizationRequestUri, jar);

        Assert.Equal("https://signed.example/callback", RequestParameters.TryGetResponseUri(request));
        Assert.Equal("direct_post.jwt", RequestParameters.TryGetResponseMode(request));
        Assert.Equal("dc+sd-jwt", RequestParameters.TryGetRequestedFormat(request));
        Assert.Equal("https://signed.example/vct", RequestParameters.TryGetExpectedVct(request));
    }

    [Fact]
    public void A_request_object_that_carries_no_dcql_is_not_verifiable()
    {
        // It decodes, so "did anything parse" would call it recoverable. It asks for no credential, so
        // the format, the vct and the docType are all null and a response would be accepted on its
        // signature alone. That is the failure the predicate exists to prevent.
        var jar = UnsignedRequestObject("""{"response_uri":"https://signed.example/callback"}""");
        var request = AsSessionRequest(new Uri("https://verifier.example/start"), jar);

        Assert.False(WalletResponseVerifier.CanVerify(request));

        // Recoverability is about the query. Other parameters stay readable, and the mock wallet reads
        // them, so tightening the predicate must not narrow the accessors.
        Assert.Equal("https://signed.example/callback", RequestParameters.TryGetResponseUri(request));
    }

    [Fact]
    public async Task A_request_object_that_does_not_parse_falls_through_to_the_query()
    {
        // Two dot-separated parts, so it looks like a JWT, but the payload is not base64url JSON. The
        // request still has a readable encoding, and using it beats reporting the session unverifiable.
        var av = await BuildAvRequestAsync();
        var request = AsSessionRequest(av.AuthorizationRequestUri, "header.not-base64url-json.signature");

        Assert.Equal("mso_mdoc", RequestParameters.TryGetRequestedFormat(request));
        Assert.Equal(ResponseUri.ToString(), RequestParameters.TryGetResponseUri(request));
    }

    /// <summary>A compact JWT whose payload is the supplied JSON. The signature is not read here.</summary>
    private static string UnsignedRequestObject(string payloadJson)
    {
        var payload = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(payloadJson);
        return $"header.{payload}.signature";
    }
}
