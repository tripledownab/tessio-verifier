using System.Security.Cryptography;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// End-to-end mdoc verification: issuerAuth signature, IACA trust anchoring, validity window,
/// digest checks and the claim mapping. Mirrors the negative families of the SD-JWT suite.
/// </summary>
public sealed class MdocVerifierTests : IDisposable
{
    private readonly MdocTestBuilder _builder = new();

    private static MdocVerifier VerifierFor(MdocTestBuilder builder) => new(
        new StaticTrustListResolver(
            [builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [builder.IacaCertificate]));

    private static PresentedCredential Credential(MdocTestBuilder builder, string format = MdocVerifier.Format) =>
        new() { Format = format, RawValue = builder.BuildBase64Url() };

    private MdocVerificationContext Context(string? docType = MdocTestBuilder.DefaultDocType) => ContextFor(_builder, docType);

    private static MdocVerificationContext ContextFor(MdocTestBuilder builder, string? docType = MdocTestBuilder.DefaultDocType) =>
        new()
        {
            ExpectedDocType = docType,
            ClientId = builder.ClientId,
            Nonce = builder.Nonce,
            EncryptionKeyThumbprint = builder.EncryptionKeyThumbprint,
            ResponseUri = builder.ResponseUri,
        };

    [Fact]
    public async Task ValidMdoc_Verifies_WithNamespacedClaims()
    {
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.True(result.Issuer.Trusted);
        Assert.Equal("x5c", result.Issuer.KeyResolutionMethod);
        Assert.Contains("Test Document Signer", result.Issuer.Identifier, StringComparison.Ordinal);

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[MdocTestBuilder.DefaultNamespace]);
        Assert.Equal("Mobius", elements["family_name"]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Fact]
    public async Task ExternalSessionTranscript_IsUsedVerbatimForDeviceAuth()
    {
        // The builder signs over the redirect transcript of its own values. Handing the verifier
        // those same bytes externally, with every redirect field left null, must verify: the
        // override is used as given and nothing else is consulted to build one.
        var transcript = SessionTranscriptBuilder.Build(
            _builder.ClientId, _builder.Nonce, _builder.EncryptionKeyThumbprint, _builder.ResponseUri);
        var context = new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            SessionTranscript = transcript,
        };

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), context);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task ExternalSessionTranscript_TheDeviceDidNotSign_FailsDeviceAuth()
    {
        var context = new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            SessionTranscript = SessionTranscriptBuilder.BuildForIso18013AnnexC([0x01], "https://verifier.example.com"),
        };

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), context);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task SpoofedDocumentSigner_IsUntrusted()
    {
        // A second issuer with its own IACA: same doctype and claims, but its chain does not anchor
        // on the trust list configured for the first issuer.
        using var spoof = new MdocTestBuilder();
        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [spoof.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]));

        var result = await verifier.VerifyAsync(Credential(spoof), ContextFor(spoof));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.IssuerUntrusted);
    }

    [Fact]
    public async Task WrongSignerKey_FailsSignatureCheck()
    {
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _builder.SignerKeyOverride = wrongKey;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.SignatureInvalid);
    }

    [Fact]
    public async Task ExpiredMso_IsRejected()
    {
        _builder.ValidUntil = DateTimeOffset.UtcNow.AddHours(-1);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.CredentialExpired);
    }

    [Fact]
    public async Task NotYetValidMso_IsRejected()
    {
        _builder.ValidFrom = DateTimeOffset.UtcNow.AddHours(1);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.CredentialNotYetValid);
    }

    [Fact]
    public async Task DocTypeMismatch_AgainstDcqlExpectation_IsRejected()
    {
        var result = await VerifierFor(_builder).VerifyAsync(
            Credential(_builder), Context(docType: "eu.europa.ec.eudi.pid.1"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
    }

    [Fact]
    public async Task TamperedClaim_FailsDigests_EvenWithValidSignature()
    {
        _builder.TamperItem = (encoded, name) => encoded; // baseline sanity: no tampering passes
        var baseline = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());
        Assert.True(baseline.IsValid);

        // Now actually swap a value after the MSO digests are fixed. The issuerAuth signature stays
        // valid (it covers the MSO, not the items), so only the digest check catches this.
        _builder.TamperItem = (encoded, name) => name == "age_over_18" ? ReplaceBool(encoded) : encoded;
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DigestMismatch);
        Assert.Empty(result.DisclosedClaims); // tampered presentations disclose nothing
    }

    [Fact]
    public async Task WrongFormat_IsRejected()
    {
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder, format: "dc+sd-jwt"), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.FormatUnsupported);
    }

    [Fact]
    public async Task TrustResolver_ReceivesTheDsFirstChain()
    {
        ReadOnlyMemory<byte>[]? seen = null;
        var capturing = new CapturingResolver(chain => seen = chain);

        await new MdocVerifier(capturing).VerifyAsync(Credential(_builder), Context());

        Assert.NotNull(seen);
        Assert.Equal(2, seen!.Length);
        Assert.Equal(_builder.DsCertificate.RawData, seen[0].ToArray());
        Assert.Equal(_builder.IacaCertificate.RawData, seen[1].ToArray());
    }

    private sealed class CapturingResolver(Action<ReadOnlyMemory<byte>[]> onResolve) : ITrustListResolver
    {
        public Task<IssuerTrustStatus> ResolveAsync(string issuer, ReadOnlyMemory<byte>[] x5c, CancellationToken ct = default)
        {
            onResolve(x5c);
            return Task.FromResult(new IssuerTrustStatus { Trusted = true, TrustListSource = "capturing" });
        }
    }

    public void Dispose() => _builder.Dispose();

    /// <summary>Rewrites a bool elementValue to its negation inside IssuerSignedItemBytes.</summary>
    private static byte[] ReplaceBool(byte[] encoded)
    {
        var outerReader = new System.Formats.Cbor.CborReader(encoded, System.Formats.Cbor.CborConformanceMode.Lax);
        outerReader.ReadTag();
        var innerReader = new System.Formats.Cbor.CborReader(outerReader.ReadByteString(), System.Formats.Cbor.CborConformanceMode.Lax);

        var inner = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        innerReader.ReadStartMap();
        inner.WriteStartMap(4);
        while (innerReader.PeekState() != System.Formats.Cbor.CborReaderState.EndMap)
        {
            var key = innerReader.ReadTextString();
            inner.WriteTextString(key);
            if (key == "elementValue")
            {
                inner.WriteBoolean(!innerReader.ReadBoolean());
            }
            else
            {
                inner.WriteEncodedValue(innerReader.ReadEncodedValue().Span);
            }
        }

        inner.WriteEndMap();

        var outer = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Lax);
        outer.WriteTag((System.Formats.Cbor.CborTag)24);
        outer.WriteByteString(inner.Encode());
        return outer.Encode();
    }

    /// <summary>
    /// The trust provenance the resolver returns has to REACH the caller, on both verdicts.
    /// </summary>
    /// <remarks>
    /// The resolver's own tests prove it computes these. They say nothing about whether this verifier
    /// copies them into <c>IssuerInfo</c>, which is a different claim: a mechanism can be correct and
    /// reach no caller. Deleting the three assignments in <c>MdocVerifier</c> leaves every other test in
    /// this file green, so this is the one that holds the wiring.
    /// </remarks>
    [Fact]
    public async Task IssuerInfo_CarriesTheTrustProvenance_OnSuccessAndOnFailure()
    {
        var expected = _builder.IacaCertificate.GetCertHashString(HashAlgorithmName.SHA256);

        var ok = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(ok.IsValid, string.Join("; ", ok.Errors.Select(e => e.Code)));
        Assert.Equal("mdoc-test", ok.Issuer.TrustListSource);
        Assert.Equal(_builder.IacaCertificate.Subject, ok.Issuer.TrustAnchorSubject);
        Assert.Equal(expected, ok.Issuer.TrustAnchorThumbprint);

        // A refusal names the list that refused and no anchor. This is the verdict a relying party comes
        // back to question, so it is the half worth pinning: an implementation that carried provenance
        // only on the passing branch would satisfy the assertions above and fail these.
        using var spoof = new MdocTestBuilder();
        var refused = await VerifierFor(spoof).VerifyAsync(Credential(_builder), ContextFor(spoof));

        Assert.False(refused.IsValid);
        Assert.Equal("mdoc-test", refused.Issuer.TrustListSource);
        Assert.Null(refused.Issuer.TrustAnchorSubject);
        Assert.Null(refused.Issuer.TrustAnchorThumbprint);
    }

    [Fact]
    public async Task CredentialType_ReportsTheDocType_OnSuccessAndOnFailure()
    {
        // For mdoc the type is the docType, which parsing establishes before any check runs, so unlike
        // the SD-JWT VC path there is no case where an issuer is known and the type is not.
        var ok = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(ok.IsValid, string.Join("; ", ok.Errors.Select(e => e.Code)));
        Assert.Equal(MdocTestBuilder.DefaultDocType, ok.CredentialType);

        var mismatched = await VerifierFor(_builder).VerifyAsync(
            Credential(_builder), Context("org.example.other"));

        Assert.False(mismatched.IsValid);
        Assert.Contains(mismatched.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
        Assert.Equal(MdocTestBuilder.DefaultDocType, mismatched.CredentialType);
    }
}
