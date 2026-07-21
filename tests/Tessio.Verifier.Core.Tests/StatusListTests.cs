namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Token Status List enforcement (draft-ietf-oauth-status-list): revoked and suspended credentials
/// fail verification, unreachable or forged status lists fail closed, and the bit packing follows
/// the spec's LSB-first layout.
/// </summary>
public class StatusListTests
{
    private const string StatusUri = "https://issuer.example/statuslists/1";

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    private static (SdJwtVcVerifier Verifier, FakeHttpHandler Http) VerifierFor(
        TestCredentialBuilder builder, string? statusListJwt, SdJwtVcVerifierOptions? options = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        if (statusListJwt is not null)
        {
            http.Map(StatusUri, statusListJwt);
        }

        return (new SdJwtVcVerifier(new FakeTrustListResolver(), options, new HttpClient(http)), http);
    }

    private static TestCredentialBuilder CredentialWithStatus(long idx)
    {
        var builder = new TestCredentialBuilder();
        builder.Status = (idx, StatusUri);
        return builder;
    }

    [Fact]
    public async Task ValidStatus_Passes()
    {
        using var builder = CredentialWithStatus(idx: 1);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 0, 1, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task RevokedCredential_Fails()
    {
        using var builder = CredentialWithStatus(idx: 2);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0, 0, 1, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_revoked");
    }

    [Fact]
    public async Task SuspendedCredential_Fails_WithTwoBitPacking()
    {
        // bits=2, idx=5 → byte 1, shift 2. Value 2 = SUSPENDED.
        using var builder = CredentialWithStatus(idx: 5);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 2, statuses: [0, 0, 0, 0, 0, 2, 0, 0]);
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_suspended");
    }

    [Fact]
    public async Task UnreachableStatusList_FailsClosed()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, _) = VerifierFor(builder, statusListJwt: null); // status uri → 404

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_unresolvable");
    }

    [Fact]
    public async Task SubMismatch_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], sub: "https://issuer.example/other-list");
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    [Fact]
    public async Task WrongTyp_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], typ: "JWT");
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    [Fact]
    public async Task ExpiredStatusList_FailsClosed()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var statusList = builder.BuildStatusListToken(
            StatusUri, bits: 1, statuses: [0], exp: DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds());
        var (verifier, _) = VerifierFor(builder, statusList);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_unresolvable");
    }

    [Fact]
    public async Task ForeignIssuerStatusList_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var foreignIssuer = new TestCredentialBuilder { Issuer = "https://someone-else.example" };
        var forged = foreignIssuer.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]);

        var (verifier, http) = VerifierFor(builder, forged);
        http.Map(
            "https://someone-else.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://someone-else.example","jwks":{{foreignIssuer.BuildJwksJson()}}}""");

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    [Fact]
    public async Task CheckStatusDisabled_SkipsFetchEntirely()
    {
        using var builder = CredentialWithStatus(idx: 0);
        var (verifier, http) = VerifierFor(builder, statusListJwt: null, new SdJwtVcVerifierOptions { CheckStatus = false });

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.DoesNotContain(StatusUri, http.Requested);
    }

    [Fact]
    public async Task NoStatusClaim_NoCheck_NoFetch()
    {
        using var builder = new TestCredentialBuilder(); // no Status
        var (verifier, http) = VerifierFor(builder, statusListJwt: null);

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid);
        Assert.DoesNotContain(StatusUri, http.Requested);
    }
}
