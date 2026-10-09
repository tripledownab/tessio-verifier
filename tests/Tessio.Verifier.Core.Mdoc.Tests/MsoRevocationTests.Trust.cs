using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Which list may speak for a credential (EAA-6.2.10.1-06, Implementing Regulation (EU) 2024/2979, Annex II as replaced by 2026/1731),
/// and a cache that never lets a list validated for one credential's root answer for another's.
/// </summary>
public sealed partial class MsoRevocationTests
{
    // ---- Trust: EAA-6.2.10.1-06 ----

    [Fact]
    public async Task AListAnchoredOnAnotherTrustedRoot_IsRefused()
    {
        // The deployment trusts both IACAs. The list is signed under the second, the credential under the
        // first. Trusting any configured root is exactly what -06.2 rules out.
        using var other = new MdocTestBuilder("CN=Test Other IACA");
        using var foreign = new RevocationListBuilder(other.IacaCertificate, other.IacaKey);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, foreign.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(Verifier(extraAnchors: other.IacaCertificate)), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task UnderASharedRoot_OnlyTheDocumentSignersOwnIacaMaySignTheList()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CertificateAuthority("CN=Test Shared Root", rootKey, issuer: null, issuerKey: null);
        using var iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var iaca = CertificateAuthority("CN=Test IACA One", iacaKey, root, rootKey);
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var otherIaca = CertificateAuthority("CN=Test IACA Two", otherKey, root, rootKey);

        using var builder = new MdocTestBuilder(iaca, iacaKey);
        builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [root]),
            clock: null, httpClient: new HttpClient(_http));

        using (var own = new RevocationListBuilder(iaca, iacaKey) { IncludeIssuerInChain = true })
        {
            _http.Serve(ListUri, own.StatusList(ListUri, bits: 1, 0));
            var accepted = await verifier.VerifyAsync(Credential(builder), Context(builder));
            Assert.True(accepted.IsValid, Codes(accepted));
        }

        // A fresh verifier, so the list above is not answered from cache.
        verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [root]),
            clock: null, httpClient: new HttpClient(_http));
        using var sibling = new RevocationListBuilder(otherIaca, otherKey) { IncludeIssuerInChain = true };
        _http.Serve(ListUri, sibling.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await verifier.VerifyAsync(Credential(builder), Context(builder)), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task AListUnderTheSameIssuerName_ButAnotherAnchor_IsRefused()
    {
        // Names and key identifiers all match; this isolates the other half of -06.2: a seam that anchors the
        // list somewhere other than where it anchored the Document Signer is refused. Only the Document Signer in
        // the MSO and only the signer in the list, so the seam must place the list's own chain.
        _builder.X5ChainWithoutIssuer = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        var seam = new AnchorPerLeaf(_builder.DsCertificate);

        AssertRefused(await VerifyAsync(Verifier(trust: seam)), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task AnIssuerOfTheSameName_ButAnotherKey_IsTheWrongIssuer()
    {
        // Same anchor by the seam's account, same issuer name, different issuing key: the key identifiers are
        // what tell the two IACAs apart. Without them this list would pass as the credential's own issuer's.
        using var iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var iaca = CertificateAuthority("CN=Test Named IACA", iacaKey, issuer: null, issuerKey: null, withKeyId: true);
        using var impostorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var impostor = CertificateAuthority("CN=Test Named IACA", impostorKey, issuer: null, issuerKey: null, withKeyId: true);
        using var builder = new MdocTestBuilder(iaca, iacaKey)
        {
            MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri),
            X5ChainWithoutIssuer = true,
        };
        var verifier = new MdocVerifier(new SameAnchorForAll(), clock: null, httpClient: new HttpClient(_http));

        using (var own = new RevocationListBuilder(iaca, iacaKey))
        {
            _http.Serve(ListUri, own.StatusList(ListUri, bits: 1, 0));
            var accepted = await verifier.VerifyAsync(Credential(builder), Context(builder));
            Assert.True(accepted.IsValid, Codes(accepted));
        }

        verifier = new MdocVerifier(new SameAnchorForAll(), clock: null, httpClient: new HttpClient(_http));
        using var foreign = new RevocationListBuilder(impostor, impostorKey);
        _http.Serve(ListUri, foreign.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await verifier.VerifyAsync(Credential(builder), Context(builder)), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task UnderASharedRoot_ASiblingsListPaddedWithTheDocumentSigner_IsRefused(bool statusList, bool padWithIaca)
    {
        var kind = statusList ? RevocationListKind.StatusList : RevocationListKind.IdentifierList;
        // A sibling IACA's list, its x5chain padded with the credential's own Document Signer certificate,
        // which every presentation carries. The padding was issued by the right issuer but is not on the
        // list's signing path, so it must not count. The genuine list revokes; the padded one clears.
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CertificateAuthority("CN=Test Shared Root", rootKey, issuer: null, issuerKey: null, withKeyId: true);
        using var oneKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var one = CertificateAuthority("CN=Test IACA One", oneKey, root, rootKey, withKeyId: true);
        using var twoKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var two = CertificateAuthority("CN=Test IACA Two", twoKey, root, rootKey, withKeyId: true);
        using var victim = new MdocTestBuilder(one, oneKey)
        {
            MsoStatus = kind == RevocationListKind.StatusList
                ? RevocationListBuilder.StatusListReference(0, ListUri)
                : RevocationListBuilder.IdentifierListReference(OurId, ListUri),
        };
        MdocVerifier Fresh() => new(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [root]), clock: null, httpClient: new HttpClient(_http));
        byte[] ListBy(RevocationListBuilder list, bool revoked) => kind == RevocationListKind.StatusList
            ? list.StatusList(ListUri, bits: 1, revoked ? 1 : 0)
            : list.IdentifierList(ListUri, revoked ? OurId : [0x09]);

        using (var own = new RevocationListBuilder(one, oneKey) { IncludeIssuerInChain = true })
        {
            _http.Serve(ListUri, ListBy(own, revoked: true));
            AssertRefused(await Fresh().VerifyAsync(Credential(victim), Context(victim)), ErrorCodes.CredentialRevoked);
        }

        using var sibling = new RevocationListBuilder(two, twoKey)
        {
            IncludeIssuerInChain = true,
            // The Document Signer, or its IACA: both public, both issued under the credential's own root.
            ExtraChainCertificate = padWithIaca ? one.RawData : victim.DsCertificate.RawData,
        };
        _http.Serve(ListUri, ListBy(sibling, revoked: false));

        AssertRefused(await Fresh().VerifyAsync(Credential(victim), Context(victim)), ErrorCodes.StatusInvalid);
    }

    [Theory]
    [InlineData(true, false)] // the list's chain ends at the IACA
    [InlineData(false, false)] // the MSO's chain carries the IACA
    [InlineData(false, true)] // neither
    public async Task WhereTheSeamPinsTheDocumentSigner_NoListCanBePlaced(bool listCarriesIaca, bool msoWithoutIaca)
    {
        // A seam anchored on the Document Signer itself vouches for nothing above it, and a certificate with the
        // IACA's key proves only the key. So whatever the presentation carries, the list cannot be placed: a
        // limit of the deployment's trust configuration, reported as such.
        _builder.X5ChainWithoutIssuer = msoWithoutIaca;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _list.IncludeIssuerInChain = listCarriesIaca;
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        var pinned = new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [_builder.DsCertificate]);

        AssertRefused(await VerifyAsync(Verifier(trust: pinned)), ErrorCodes.StatusUnresolvable);
    }

    [Fact]
    public async Task ASeamThatRefusesTheList_IsHeldToItEvenOnTheSameAnchor()
    {
        _builder.X5ChainWithoutIssuer = true;
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(Verifier(trust: new RefusesAllButTheDocumentSigner(_builder.DsCertificate))), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task AnUntrustedListServedOnce_DoesNotStandInForTheGenuineOne()
    {
        using var other = new MdocTestBuilder("CN=Test Other IACA");
        using var foreign = new RevocationListBuilder(other.IacaCertificate, other.IacaKey);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        var verifier = Verifier();

        _http.Serve(ListUri, foreign.StatusList(ListUri, bits: 1, 0));
        AssertRefused(await VerifyAsync(verifier), ErrorCodes.StatusInvalid);

        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        var result = await VerifyAsync(verifier);

        Assert.True(result.IsValid, Codes(result));
    }

    [Fact]
    public async Task WhenOnlyTheSeamCanVouch_CertificatesWithoutKeyIdentifiersCannotBePlaced()
    {
        // The genuine IACA's own list, but neither it nor the Document Signer carries a key identifier, and
        // neither chain carries the IACA: the name alone cannot tell this IACA from a same-named one.
        using var iacaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var iaca = CertificateAuthority("CN=Test Unidentified IACA", iacaKey, issuer: null, issuerKey: null);
        using var builder = new MdocTestBuilder(iaca, iacaKey)
        {
            MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri),
            X5ChainWithoutIssuer = true,
        };
        using var list = new RevocationListBuilder(iaca, iacaKey);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        var verifier = new MdocVerifier(new SameAnchorForAll(), clock: null, httpClient: new HttpClient(_http));

        AssertRefused(await verifier.VerifyAsync(Credential(builder), Context(builder)), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task TheReferencedCertificate_AnchorsAListNoConfiguredRootCovers()
    {
        // SPEC: EAA-6.2.10.1-06.1.1. A revocation CA the deployment never configured, named in the MSO.
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority("CN=Test Revocation CA", caKey, issuer: null, issuerKey: null);
        using var list = new RevocationListBuilder(ca, caKey);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));

        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: ca.RawData);
        var named = await VerifyAsync();
        Assert.True(named.IsValid, Codes(named));

        // Without the element, the same list must anchor on the credential's IACA, and it does not.
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task TheReferencedCertificate_RefusesAListItDidNotIssue()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority("CN=Test Revocation CA", caKey, issuer: null, issuerKey: null);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: ca.RawData);
        // Signed under the credential's own IACA, which the named certificate is not.
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task TheReferencedCertificate_OutsideItsValidityWindow_IsRefused()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test Expired Revocation CA", caKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddYears(-1));
        using var list = new RevocationListBuilder(ca, caKey);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: ca.RawData);

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task ASignerCertificateTheReferencedCertificateDidNotSign_IsRefused()
    {
        // The signer names the referenced CA as its issuer, but another key signed it.
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority("CN=Test Revocation CA", caKey, issuer: null, issuerKey: null);
        using var impostorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var list = new RevocationListBuilder(ca, impostorKey);
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri, certificate: ca.RawData);

        AssertRefused(await VerifyAsync(), ErrorCodes.StatusInvalid);
    }

    [Fact]
    public async Task ASeamThatNamesNoAnchor_CannotVouchForAList()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));

        _builder.X5ChainWithoutIssuer = true;

        AssertRefused(await VerifyAsync(Verifier(trust: new TrustsEverythingNamingNoAnchor())), ErrorCodes.StatusUnresolvable);
    }

    // ---- Cache ----

    [Fact]
    public async Task AValidatedList_IsServedFromCache()
    {
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        var verifier = Verifier();

        Assert.True((await VerifyAsync(verifier)).IsValid);
        Assert.True((await VerifyAsync(verifier)).IsValid);

        Assert.Single(_http.Requested);
    }

    [Theory]
    [InlineData(null, 3600, 1)] // no ttl, exp an hour out: the configured five minutes hold
    [InlineData(null, 3600, 6 * 60)] // past the configured five minutes: refetched
    [InlineData(30UL, 3600, 60)] // the list's ttl of 30 seconds shortens the five minutes
    [InlineData(null, 120, 150)] // exp at two minutes caps the five; the refetch then finds it expired
    public async Task TheCache_HoldsForTheShortestOfDurationTtlAndExp(ulong? ttl, int expSeconds, int laterSeconds)
    {
        var clock = new MovableClock(DateTimeOffset.UtcNow);
        _list.Ttl = ttl;
        _list.ExpiresAt = clock.GetUtcNow().AddSeconds(expSeconds);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate], clock: clock),
            new MdocVerifierOptions { ClockSkew = TimeSpan.Zero }, clock, new HttpClient(_http));

        await VerifyAsync(verifier);
        clock.Advance(TimeSpan.FromSeconds(laterSeconds));
        await VerifyAsync(verifier);

        var refetched = laterSeconds >= Math.Min(Math.Min(300, (int)(ttl ?? 300)), expSeconds);
        Assert.Equal(refetched ? 2 : 1, _http.Requested.Count);
    }

    [Fact]
    public async Task ACachedList_DoesNotAnswerForACredentialUnderAnotherRoot()
    {
        // One verifier trusting two IACAs. The first credential's list is cached; the second credential,
        // from the other IACA, points at the same uri and must not be answered by it.
        using var other = new MdocTestBuilder("CN=Test Other IACA");
        var verifier = Verifier(extraAnchors: other.IacaCertificate);
        _builder.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        _http.Serve(ListUri, _list.StatusList(ListUri, bits: 1, 0));
        Assert.True((await VerifyAsync(verifier)).IsValid);

        other.MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri);
        var result = await verifier.VerifyAsync(Credential(other), Context(other));

        // Not answered from the cached list: trust is decided again for every credential, and a list not trusted
        // for this one is fetched afresh, which serves the same untrusted list here.
        AssertRefused(result, ErrorCodes.StatusInvalid);
        Assert.Equal(2, _http.Requested.Count);
    }

    [Fact]
    public async Task UnderASharedRoot_ACachedList_DoesNotAnswerForAnotherIacasCredential()
    {
        // Both credentials anchor on the same root, so the anchor alone cannot keep their cache entries
        // apart. The list is IACA One's; IACA Two's credential pointing at the same uri must not be
        // answered by it from cache.
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CertificateAuthority("CN=Test Shared Root", rootKey, issuer: null, issuerKey: null);
        using var oneKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var one = CertificateAuthority("CN=Test IACA One", oneKey, root, rootKey);
        using var twoKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var two = CertificateAuthority("CN=Test IACA Two", twoKey, root, rootKey);
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([], source: "mdoc-test", trustAnchors: [root]),
            clock: null, httpClient: new HttpClient(_http));

        using var list = new RevocationListBuilder(one, oneKey) { IncludeIssuerInChain = true };
        _http.Serve(ListUri, list.StatusList(ListUri, bits: 1, 0));
        using var first = new MdocTestBuilder(one, oneKey) { MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri) };
        var accepted = await verifier.VerifyAsync(Credential(first), Context(first));
        Assert.True(accepted.IsValid, Codes(accepted));

        using var second = new MdocTestBuilder(two, twoKey) { MsoStatus = RevocationListBuilder.StatusListReference(0, ListUri) };
        AssertRefused(await verifier.VerifyAsync(Credential(second), Context(second)), ErrorCodes.StatusInvalid);
        Assert.Equal(2, _http.Requested.Count);
    }

    /// <summary>Trusts only the Document Signer's chain, but names the same anchor for every chain.</summary>
    private sealed class RefusesAllButTheDocumentSigner(X509Certificate2 documentSigner) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus
            {
                Trusted = x5c[0].Span.SequenceEqual(documentSigner.RawData),
                TrustListSource = "test",
                TrustAnchorThumbprint = "AA",
            });
    }

    /// <summary>A clock the test moves.</summary>
    private sealed class MovableClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset _now = start;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }

    /// <summary>Trusts every chain and names the same anchor for all of them.</summary>
    private sealed class SameAnchorForAll : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "test", TrustAnchorThumbprint = "AA" });
    }

    /// <summary>A seam that trusts every chain and, like a custom resolver may, reports no anchor.</summary>
    private sealed class TrustsEverythingNamingNoAnchor : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default) =>
            Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "test" });
    }
}
