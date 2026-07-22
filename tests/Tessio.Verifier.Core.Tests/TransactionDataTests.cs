using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Transaction data acknowledgment (OpenID4VP 1.0 Annex B.3.3.1): the KB-JWT's
/// transaction_data_hashes must match the request's transaction_data strings, hashed as received.
/// </summary>
public class TransactionDataTests
{
    private static readonly string TdPayment = Base64UrlEncoder.Encode(
        """{"type":"payment_confirmation","credential_ids":["credential"],"amount":"120.00 EUR"}""");

    private static readonly string TdOther = Base64UrlEncoder.Encode(
        """{"type":"account_link","credential_ids":["credential"]}""");

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static (SdJwtVcVerifier Verifier, TestCredentialBuilder Builder) Setup()
    {
        var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        return (new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http)), builder);
    }

    private static TransactionDataExpectation Expect(params string[] tds) =>
        new() { TransactionData = tds };

    private static PresentedCredential Credential(TestCredentialBuilder builder) =>
        new() { Format = "dc+sd-jwt", RawValue = builder.Build() };

    [Fact]
    public async Task MatchingHashes_Verify()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdPayment, TdOther];

        var result = await verifier.VerifyAsync(Credential(builder), Context(), Expect(TdPayment, TdOther));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task MissingHashes_AreRejected()
    {
        var (verifier, builder) = Setup(); // wallet ignores the transaction data entirely

        var result = await verifier.VerifyAsync(Credential(builder), Context(), Expect(TdPayment));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.TransactionDataMissing);
    }

    [Fact]
    public async Task WrongHash_IsRejected()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdOther]; // wallet acknowledged different data

        var result = await verifier.VerifyAsync(Credential(builder), Context(), Expect(TdPayment));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.TransactionDataHashMismatch);
    }

    [Fact]
    public async Task HashCountMismatch_IsRejected()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdPayment]; // one acknowledged, two requested

        var result = await verifier.VerifyAsync(Credential(builder), Context(), Expect(TdPayment, TdOther));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.TransactionDataHashMismatch);
    }

    [Fact]
    public async Task RequestConstrainedAlg_RequiresTheResponseToDeclareIt()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdPayment]; // hashes present, but no alg declared

        var result = await verifier.VerifyAsync(Credential(builder), Context(),
            new TransactionDataExpectation { TransactionData = [TdPayment], AllowedHashAlgorithms = ["sha-256"] });

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.TransactionDataAlgUnsupported);
    }

    [Fact]
    public async Task RequestConstrainedAlg_DeclaredAndMatching_Verifies()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdPayment];
        builder.TransactionDataHashesAlg = "sha-256";

        var result = await verifier.VerifyAsync(Credential(builder), Context(),
            new TransactionDataExpectation { TransactionData = [TdPayment], AllowedHashAlgorithms = ["sha-256"] });

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task UnconstrainedRequest_RejectsNonSha256Declaration()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdPayment];
        builder.TransactionDataHashesAlg = "sha-384"; // spec: default MUST be sha-256

        var result = await verifier.VerifyAsync(Credential(builder), Context(), Expect(TdPayment));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.TransactionDataAlgUnsupported);
    }

    [Fact]
    public async Task NoKbJwt_WithTransactionData_FailsClosed()
    {
        var (verifier, builder) = Setup();
        builder.IncludeKbJwt = false;

        var result = await verifier.VerifyAsync(Credential(builder), Context(), Expect(TdPayment));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == ErrorCodes.TransactionDataMissing);
    }

    [Fact]
    public async Task NoExpectation_IgnoresWalletProvidedHashes()
    {
        var (verifier, builder) = Setup();
        builder.TransactionData = [TdPayment]; // wallet volunteers hashes nobody asked for

        var result = await verifier.VerifyAsync(Credential(builder), Context());

        Assert.True(result.IsValid);
    }
}
