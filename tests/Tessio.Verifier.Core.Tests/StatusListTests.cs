using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Trust;

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
        TestCredentialBuilder builder,
        string? statusListJwt,
        SdJwtVcVerifierOptions? options = null,
        FakeTrustListResolver? trust = null)
    {
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        if (statusListJwt is not null)
        {
            http.Map(StatusUri, statusListJwt);
        }

        return (new SdJwtVcVerifier(trust ?? new FakeTrustListResolver(), options, new HttpClient(http)), http);
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

    // A status list token is believed for TWO independent reasons, so each gets its own test and they
    // are broken one at a time. SubMismatch_IsRejected above breaks the BINDING: a token that does not
    // name the uri the issuer put inside the credential it signed. The pair below breaks, and then does
    // not break, AUTHENTICITY: whether the signer of a correctly bound token is trusted.
    //
    // These REPLACED ForeignIssuerStatusList_IsRejected, which pinned a different rule: that the status
    // token's issuer must equal the credential's. That rule was not in the specification and could not
    // be satisfied by a conformant token, because a token omitting iss resolves to its leaf subject DN
    // and a DN never equals an HTTPS URI. It refused the EUDI Wallet Reference Implementation's own PID.
    [Fact]
    public async Task UntrustedStatusListSigner_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var otherSigner = new TestCredentialBuilder { Issuer = "https://someone-else.example" };
        var forged = otherSigner.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]);

        // The credential's own issuer stays trusted, so a failure here can only come from the status
        // list signer. A resolver that refused everything would prove nothing about which check fired.
        var trust = new FakeTrustListResolver();
        trust.Untrusted.Add("https://someone-else.example");

        var (verifier, http) = VerifierFor(builder, forged, trust: trust);
        http.Map(
            "https://someone-else.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://someone-else.example","jwks":{{otherSigner.BuildJwksJson()}}}""");

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid");
    }

    // SPEC: draft-ietf-oauth-status-list section 2 — "The Status Issuer can be either the Issuer or an
    // entity that has been authorized by the Issuer to issue Status List Tokens." The issuer authorises
    // by putting that uri inside the credential it signs, so a different BUT TRUSTED signer serving that
    // uri is the delegation the specification describes, not an attack.
    [Fact]
    public async Task DelegatedTrustedStatusListSigner_IsAccepted()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var statusIssuer = new TestCredentialBuilder { Issuer = "https://status.example" };
        var delegated = statusIssuer.BuildStatusListToken(StatusUri, bits: 1, statuses: [0]);

        var (verifier, http) = VerifierFor(builder, delegated);
        http.Map(
            "https://status.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"https://status.example","jwks":{{statusIssuer.BuildJwksJson()}}}""");

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    // ---- The anchoring path, judged by the REAL resolver -------------------------------------------
    //
    // Every other status list test here signs without an x5c, so the trust seam sees an empty chain and
    // answers by identifier membership. The status list tokens this code actually meets carry x5c and
    // are answered by ANCHORING, which no test reached until 2026-09-20. `FakeTrustListResolver` cannot
    // stand in either: it ignores the chain, which is the opposite of what `StaticTrustListResolver`
    // does when one is present. So these two use the shipped resolver rather than a double, and they
    // are the only thing pinning the claim that a self-signed status token served from the issuer's own
    // uri is refused.

    private static X509Certificate2 SelfSignedStatusSigner(string commonName)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", ec, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public async Task SelfSignedStatusListToken_DoesNotAnchor_IsRejected()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var attacker = SelfSignedStatusSigner("attacker-who-serves-the-status-uri");
        var forged = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], signWith: attacker);

        // A real resolver holding one unrelated anchor. The attacker's chain reaches none of it.
        using var unrelated = SelfSignedStatusSigner("some-configured-anchor");
        var trust = new StaticTrustListResolver([TestCredentialBuilder.DefaultIssuer], "test", [unrelated]);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, forged);
        var verifier = new SdJwtVcVerifier(trust, options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        // The MESSAGE, not only the code. `status_invalid` covers typ, algorithm, sub and trust, so
        // asserting the code alone would keep passing if this token started failing for some other
        // reason and the anchoring check silently stopped running.
        var error = Assert.Single(result.Errors, e => e.Code == "status_invalid");
        Assert.Contains("not trusted", error.Message, StringComparison.Ordinal);
        Assert.False(result.IsValid);
    }

    [Fact]
    public async Task AnchoredStatusListToken_IsAccepted()
    {
        using var builder = CredentialWithStatus(idx: 0);
        using var statusSigner = SelfSignedStatusSigner("delegated-status-issuer");
        var token = builder.BuildStatusListToken(StatusUri, bits: 1, statuses: [0], signWith: statusSigner);

        // Same certificate, this time pinned as an anchor. Only the deployment's trust changed.
        var trust = new StaticTrustListResolver([TestCredentialBuilder.DefaultIssuer], "test", [statusSigner]);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(StatusUri, token);
        var verifier = new SdJwtVcVerifier(trust, options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Code)));
    }

    // A cleartext status list is answerable by anyone on the path, and the failure is silent: the fetch
    // succeeds and the verdict is whatever the network said. Asserting the list was never REQUESTED is
    // the discriminating part, because a check placed after the fetch would still return an error while
    // having already trusted the connection.
    [Fact]
    public async Task PlaintextHttpStatusListUri_IsRejected_AndNeverFetched()
    {
        const string InsecureUri = "http://issuer.example/statuslists/1";
        using var builder = new TestCredentialBuilder { Status = (0, InsecureUri) };
        var statusList = builder.BuildStatusListToken(InsecureUri, bits: 1, statuses: [0]);

        var http = new FakeHttpHandler()
            .Map("https://issuer.example/.well-known/jwt-vc-issuer",
                $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""")
            .Map(InsecureUri, statusList);
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), options: null, new HttpClient(http));

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = "dc+sd-jwt", RawValue = builder.Build() }, Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == "status_invalid" && e.Message.Contains("HTTPS", StringComparison.Ordinal));
        Assert.DoesNotContain(InsecureUri, http.Requested);
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
