using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// End-to-end verifier tests over real signed credentials: happy paths for both key-resolution
/// mechanisms plus the negative catalogue (tampering, replay, trust, policy).
/// </summary>
public class SdJwtVcVerifierTests
{
    private static VerificationContext Context(string? expectedVct = null) => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
        ExpectedVct = expectedVct,
    };

    private static PresentedCredential Credential(string raw, string format = "dc+sd-jwt") =>
        new() { Format = format, RawValue = raw };

    private static SdJwtVcVerifier MetadataVerifier(
        TestCredentialBuilder builder,
        ITrustListResolver? trust = null,
        SdJwtVcVerifierOptions? options = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        return new SdJwtVcVerifier(trust ?? new FakeTrustListResolver(), options, new HttpClient(http));
    }

    // ---- Happy paths --------------------------------------------------------------------------

    [Fact]
    public async Task ValidCredential_MetadataResolution_Verifies()
    {
        using var builder = new TestCredentialBuilder();
        builder.PlainClaims["issuing_country"] = "DE";
        var trust = new FakeTrustListResolver();

        var result = await MetadataVerifier(builder, trust).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Empty(result.Errors);
        Assert.Equal("Möbius", result.DisclosedClaims["family_name"]);
        Assert.Equal(true, result.DisclosedClaims["age_over_18"]);
        Assert.Equal("DE", result.DisclosedClaims["issuing_country"]);
        Assert.True(result.Issuer.Trusted);
        Assert.Equal("jwt-vc-issuer-metadata", result.Issuer.KeyResolutionMethod);
        Assert.Equal(TestCredentialBuilder.DefaultIssuer, trust.SeenIssuer);
        Assert.Equal(0, trust.SeenChainLength);
    }

    [Fact]
    public async Task ValidCredential_X5cResolution_Verifies_AndHandsChainToTrustSeam()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate();
        var trust = new FakeTrustListResolver();

        var result = await new SdJwtVcVerifier(trust).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Equal(1, trust.SeenChainLength);
    }

    [Fact]
    public async Task WithheldClaim_IsAbsent_DisclosedClaimIsPresent()
    {
        using var builder = new TestCredentialBuilder();
        builder.Withhold.Add("family_name");
        builder.DecoyDigests = 2;

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid);
        Assert.False(result.DisclosedClaims.ContainsKey("family_name"));
        Assert.Equal(true, result.DisclosedClaims["age_over_18"]);
    }

    [Fact]
    public async Task NoKeyBinding_Allowed_WhenNotRequired()
    {
        using var builder = new TestCredentialBuilder { IncludeKbJwt = false, IncludeCnf = false };
        var options = new SdJwtVcVerifierOptions { RequireKeyBinding = false };

        var result = await MetadataVerifier(builder, options: options)
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task LegacyTyp_Accepted_OnlyWithCompatibilityFlag()
    {
        using var builder = new TestCredentialBuilder { Typ = "vc+sd-jwt" };
        var raw = builder.Build();

        var strict = await MetadataVerifier(builder).VerifyAsync(Credential(raw), Context());
        Assert.False(strict.IsValid);
        Assert.Equal("typ_invalid", strict.Errors.Single().Code);

        var compat = await MetadataVerifier(builder, options: new SdJwtVcVerifierOptions { AcceptLegacyVcSdJwtTyp = true })
            .VerifyAsync(Credential(raw, format: "vc+sd-jwt"), Context());
        Assert.True(compat.IsValid, string.Join("; ", compat.Errors.Select(e => e.Code)));
    }

    [Fact]
    public async Task ExpectedVct_Match_Passes()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build()), Context(expectedVct: TestCredentialBuilder.DefaultVct));

        Assert.True(result.IsValid);
    }

    // ---- Tampering & replay -------------------------------------------------------------------

    [Fact]
    public async Task TamperedSignature_FailsSignature()
    {
        using var builder = new TestCredentialBuilder();
        var raw = builder.Build();

        // Flip a character in the middle of the issuer JWT's signature segment. (Not the last char:
        // base64url's final character carries partial bits, so some flips decode to identical bytes.)
        var tildeAt = raw.IndexOf('~');
        var sigStart = raw.LastIndexOf('.', tildeAt) + 1;
        var mid = (sigStart + tildeAt) / 2;
        var tampered = raw[..mid] + (raw[mid] == 'A' ? 'B' : 'A') + raw[(mid + 1)..];

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(tampered), Context());

        Assert.False(result.IsValid);
        Assert.Equal("signature_invalid", result.Errors.Single().Code);
    }

    [Fact]
    public async Task TamperedDisclosure_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        var raw = builder.Build();

        // Replace the first disclosure with a re-encoded variant claiming a different value.
        var parts = raw.Split('~');
        parts[1] = TestCredentialBuilder.MakeDisclosure("family_name", "Mallory");
        var tampered = string.Join('~', parts);

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(tampered), Context());

        Assert.False(result.IsValid);
        Assert.Equal("disclosure_unreferenced", result.Errors.Single().Code);
    }

    [Fact]
    public async Task WrongNonce_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { KbNonce = "stale-or-replayed-nonce" };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "nonce_mismatch");
    }

    [Fact]
    public async Task WrongAudience_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { KbAudience = "https://other-verifier.example" };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "audience_mismatch");
    }

    [Fact]
    public async Task SdHashOverDifferentPresentation_FailsKeyBinding()
    {
        using var builder = new TestCredentialBuilder { SdHashOverride = "something~else~" };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "sd_hash_mismatch");
    }

    [Fact]
    public async Task MissingKeyBinding_WhenRequired_Fails()
    {
        using var builder = new TestCredentialBuilder { IncludeKbJwt = false };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "key_binding_missing");
    }

    [Fact]
    public async Task KbJwtWithoutCnf_Fails()
    {
        using var builder = new TestCredentialBuilder { IncludeCnf = false };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "confirmation_key_missing");
    }

    // ---- Policy -------------------------------------------------------------------------------

    [Fact]
    public async Task ExpiredCredential_Fails()
    {
        using var builder = new TestCredentialBuilder { Exp = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds() };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_expired");
    }

    [Fact]
    public async Task NotYetValidCredential_Fails()
    {
        using var builder = new TestCredentialBuilder { Nbf = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds() };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "credential_not_yet_valid");
    }

    [Fact]
    public async Task UntrustedIssuer_FailsWithTrustedFalse()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder, new FakeTrustListResolver(trusted: false))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.False(result.Issuer.Trusted);
        Assert.Contains(result.Errors, e => e.Code == "issuer_untrusted");
        Assert.Empty(result.DisclosedClaims);
    }

    [Fact]
    public async Task VctMismatch_Fails()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build()), Context(expectedVct: "https://credentials.example/other"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "vct_mismatch");
    }

    [Fact]
    public async Task MissingVct_Fails()
    {
        using var builder = new TestCredentialBuilder { Vct = null };

        var result = await MetadataVerifier(builder).VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "vct_missing");
    }

    [Fact]
    public async Task PolicyFailures_AreAccumulated_NotFirstOnly()
    {
        using var builder = new TestCredentialBuilder
        {
            Exp = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds(),
            KbNonce = "wrong-nonce",
        };

        var result = await MetadataVerifier(builder, new FakeTrustListResolver(trusted: false))
            .VerifyAsync(Credential(builder.Build()), Context());

        var codes = result.Errors.Select(e => e.Code).ToList();
        Assert.Contains("credential_expired", codes);
        Assert.Contains("nonce_mismatch", codes);
        Assert.Contains("issuer_untrusted", codes);
    }

    // ---- Format & resolution ------------------------------------------------------------------

    [Fact]
    public async Task WrongFormatIdentifier_IsRejected()
    {
        using var builder = new TestCredentialBuilder();

        var result = await MetadataVerifier(builder)
            .VerifyAsync(Credential(builder.Build(), format: "vc+sd-jwt"), Context());

        Assert.False(result.IsValid);
        Assert.Equal("format_unsupported", result.Errors.Single().Code);
    }

    [Fact]
    public async Task GarbageRawValue_IsRejected()
    {
        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential("not-a-credential"), Context());

        Assert.False(result.IsValid);
        Assert.Equal("structure_invalid", result.Errors.Single().Code);
    }

    [Fact]
    public async Task MetadataIssuerMismatch_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://someone-else.example","jwks":{{builder.BuildJwksJson()}}}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));

        var result = await verifier.VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal("issuer_metadata_invalid", result.Errors.Single().Code);
    }

    [Fact]
    public async Task X5cSanMismatch_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        builder.UseCertificate(sanDnsName: "not-the-issuer.example");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver())
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal("issuer_certificate_mismatch", result.Errors.Single().Code);
    }

    [Fact]
    public async Task IssuerMetadataUnreachable_IsRejected()
    {
        using var builder = new TestCredentialBuilder();
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(new FakeHttpHandler()));

        var result = await verifier.VerifyAsync(Credential(builder.Build()), Context());

        Assert.False(result.IsValid);
        Assert.Equal("issuer_key_unresolvable", result.Errors.Single().Code);
    }

    [Fact]
    public async Task WellKnownPath_InsertsSegmentBetweenHostAndPath()
    {
        // SPEC: draft-ietf-oauth-sd-jwt-vc §3 — iss with a path component.
        using var builder = new TestCredentialBuilder { Issuer = "https://issuer.example/tenant/1234" };
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer/tenant/1234",
            $$"""{"issuer":"https://issuer.example/tenant/1234","jwks":{{builder.BuildJwksJson()}}}""");

        var result = await new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http))
            .VerifyAsync(Credential(builder.Build()), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.Contains("https://issuer.example/.well-known/jwt-vc-issuer/tenant/1234", http.Requested);
    }
}
