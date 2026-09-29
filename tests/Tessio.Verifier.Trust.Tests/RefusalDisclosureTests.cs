using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust.Tests;

/// <summary>
/// What a refusal reason may say. Everything about which side of the exchange a rejection describes
/// belongs here, including the opt-in switches that widen it.
/// </summary>
/// <remarks>
/// A reason travels. It becomes a <c>VerificationResult.Errors[].Message</c>, and the library's session
/// status endpoint and SSE stream serialise that to whoever holds a session id, which anyone can
/// self-serve. So a reason describes the certificate the caller presented. What this deployment holds
/// is a fact about the deployment and is added only when an operator asks for it.
/// </remarks>
public sealed class RefusalDisclosureTests : IDisposable
{
    private const string Issuer = "https://issuer.example";

    // Named as a counterparty would be, because the point of the negative assertion is that a real
    // anchor list is a list of names. "CN=Anchor" would pass the same test and teach nobody why.
    private const string AnchorSubject = "CN=Some Counterparty IACA, O=A Named Partner";

    private const string DumpAnchorsVariable = "TESSIO_TRUST_DUMP_ANCHORS";
    private const string DumpLeafVariable = "TESSIO_TRUST_DUMP_LEAF";

    private readonly ECDsa _anchorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _presentedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _anchor;
    private readonly X509Certificate2 _presented;

    public RefusalDisclosureTests()
    {
        // NAME THE AMBIENT CAUSE BEFORE IT CAUSES A MYSTERY. Two tests here assert an ABSENCE, and both
        // read the process environment. The documentation tells an operator to export one of these
        // variables, read a reason, and export it back off, so a shell or a CI job that keeps it set
        // would turn this class red with a message about a certificate subject. Fail on the real cause.
        foreach (var variable in new[] { DumpAnchorsVariable, DumpLeafVariable })
        {
            Assert.True(
                Environment.GetEnvironmentVariable(variable) is null,
                $"{variable} is set in this process. It widens a refusal reason, which is exactly what "
                + "the absence assertions here measure. Unset it and run again.");
        }

        _anchor = SelfSigned(AnchorSubject, _anchorKey);
        _presented = SelfSigned("CN=Somebody Else", _presentedKey);
    }

    private static X509Certificate2 SelfSigned(string subject, ECDsa key)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private async Task<IssuerTrustStatus> RefuseAsync()
    {
        var resolver = new StaticTrustListResolver([Issuer], trustAnchors: [_anchor]);
        return await resolver.ResolveAsync(Issuer, [_presented.RawData]);
    }

    [Fact]
    public async Task ByDefault_ARefusalDoesNotNameTheAnchorsThisDeploymentHolds()
    {
        var status = await RefuseAsync();

        Assert.False(status.Trusted);
        Assert.DoesNotContain(AnchorSubject, status.Reason, StringComparison.Ordinal);
        // It still says enough to act on: the platform's chain status and the presented leaf's own
        // issuer name. Both are facts about what the caller sent.
        Assert.Contains(_presented.Issuer, status.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The sentence saying where an incomplete chain stops describes the PRESENTED chain only. This
    /// chain is issued by a CA nobody presented, so that sentence is in the reason, and the anchor this
    /// deployment holds is still not.
    /// </summary>
    [Fact]
    public async Task AnIncompleteChain_IsDescribed_WithoutNamingTheAnchorsThisDeploymentHolds()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest("CN=An Unpresented CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var leaf = new CertificateRequest("CN=A Leaf Below It", leafKey, HashAlgorithmName.SHA256)
            .Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(20), Guid.NewGuid().ToByteArray());

        var status = await new StaticTrustListResolver([Issuer], trustAnchors: [_anchor]).ResolveAsync(Issuer, [leaf.RawData]);

        Assert.False(status.Trusted);
        Assert.Contains("carries no certificate above 'CN=A Leaf Below It'", status.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain(AnchorSubject, status.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// A chain refused for a reason other than being incomplete does not get the sentence, so it does
    /// not send an operator looking for a certificate that is not missing.
    /// </summary>
    [Fact]
    public async Task ACompleteChainRefusedForAnotherReason_DoesNotClaimACertificateIsMissing()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest("CN=A Configured CA", caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(30));
        // Issued by the configured CA, so nothing is missing, but its window closed an hour ago.
        using var expired = new CertificateRequest("CN=An Expired Leaf", leafKey, HashAlgorithmName.SHA256)
            .Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddHours(-1), Guid.NewGuid().ToByteArray());

        var status = await new StaticTrustListResolver([Issuer], trustAnchors: [ca]).ResolveAsync(Issuer, [expired.RawData]);

        Assert.False(status.Trusted);
        // The refusal is about time, which proves the chain did build and this is the case under test.
        Assert.Contains("NotTimeValid", status.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("carries no certificate above", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WhenTheOperatorAsks_ARefusalNamesThemWithTheirKeyIdentifiers()
    {
        // Set and restored here. Classes in this assembly DO run in parallel, in one process, so the
        // protection is not that xUnit serialises anything: it is that no other class asserts the
        // absence of a substring in a resolver-produced reason, and the dump only ever appends. The two
        // that do are in this class, which xUnit does run sequentially.
        Environment.SetEnvironmentVariable(DumpAnchorsVariable, "1");
        try
        {
            var status = await RefuseAsync();

            Assert.False(status.Trusted);
            Assert.Contains(AnchorSubject, status.Reason, StringComparison.Ordinal);
            // The subject alone is the case an operator misreads. Matching names with differing key
            // identifiers is a certificate authority regenerated under its old name, and that looks like
            // it should have worked until the identifiers are on screen next to each other.
            Assert.Contains("subject key id", status.Reason, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(DumpAnchorsVariable, null);
        }
    }

    [Fact]
    public async Task ByDefault_ARefusalWithNoAnchorsDoesNotSayThatItHasNone()
    {
        // The other branch. A list that anchors on nothing refuses every certificate-carried key, and it
        // used to say so and tell the reader to configure anchors: an operator instruction, delivered to
        // whoever presented the credential, stating what this deployment holds. A cardinality of zero is
        // still the set. What the presenter needs is that the route is closed here.
        var resolver = new StaticTrustListResolver([Issuer]);

        var status = await resolver.ResolveAsync(Issuer, [_presented.RawData]);

        Assert.False(status.Trusted);
        Assert.Contains("does not accept an issuer key carried in a certificate", status.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("no trust anchors", status.Reason, StringComparison.Ordinal);
        Assert.DoesNotContain("configure", status.Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task WhenTheOperatorAsks_TheEmptyAnchorListSaysSoPlainly()
    {
        Environment.SetEnvironmentVariable(DumpAnchorsVariable, "1");
        try
        {
            var resolver = new StaticTrustListResolver([Issuer]);

            var status = await resolver.ResolveAsync(Issuer, [_presented.RawData]);

            // The operator's half of the answer. Without this the variable the documentation sends them
            // to would do nothing on the one refusal where the anchor list IS the explanation.
            Assert.Contains("Configured anchors: none.", status.Reason, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(DumpAnchorsVariable, null);
        }
    }

    [Fact]
    public async Task ByDefault_ARefusalDoesNotEchoTheWholePresentedCertificate()
    {
        var status = await RefuseAsync();

        // Harmless to the caller, who sent it, and long enough to bury the sentence that matters.
        Assert.DoesNotContain(Convert.ToBase64String(_presented.RawData), status.Reason, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        _anchor.Dispose();
        _presented.Dispose();
        _anchorKey.Dispose();
        _presentedKey.Dispose();
    }
}
