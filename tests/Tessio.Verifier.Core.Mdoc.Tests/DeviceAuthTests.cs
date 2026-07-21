using System.Security.Cryptography;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Session transcript (OpenID4VP 1.0 Annex B.2.6.1) and device authentication. The transcript
/// structures are pinned against the specification's own published example bytes, and every
/// transcript input is tamper-tested through the device signature.
/// </summary>
public sealed class DeviceAuthTests : IDisposable
{
    private readonly MdocTestBuilder _builder = new();

    // ---- Known-answer vectors from OpenID4VP 1.0 Annex B.2.6.1 (non-normative example) ----

    private const string SpecClientId = "x509_san_dns:example.com";
    private const string SpecNonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
    private const string SpecResponseUri = "https://example.com/response";
    private static readonly byte[] SpecThumbprint = Convert.FromHexString(
        "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047");

    [Fact]
    public void HandoverInfo_MatchesTheSpecExampleBytes()
    {
        var handoverInfo = SessionTranscriptBuilder.BuildHandoverInfo(
            SpecClientId, SpecNonce, SpecThumbprint, SpecResponseUri);

        Assert.Equal(
            "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767426b786a7831726463397564527276654b7653734a49713830"
            + "61766c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
            + "781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365",
            Convert.ToHexString(handoverInfo).ToLowerInvariant());
    }

    [Fact]
    public void SessionTranscript_MatchesTheSpecExampleBytes()
    {
        var transcript = SessionTranscriptBuilder.Build(SpecClientId, SpecNonce, SpecThumbprint, SpecResponseUri);

        Assert.Equal(
            "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac",
            Convert.ToHexString(transcript).ToLowerInvariant());
    }

    // ---- End-to-end device authentication ----

    private static MdocVerifier VerifierFor(MdocTestBuilder builder, MdocVerifierOptions? options = null) => new(
        new StaticTrustListResolver(
            [builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [builder.IacaCertificate]),
        options);

    private static PresentedCredential Credential(MdocTestBuilder builder) =>
        new() { Format = MdocVerifier.Format, RawValue = builder.BuildBase64Url() };

    private MdocVerificationContext Context(
        string? clientId = null, string? nonce = null, string? responseUri = null, byte[]? thumbprint = null) => new()
    {
        ExpectedDocType = MdocTestBuilder.DefaultDocType,
        ClientId = clientId ?? _builder.ClientId,
        Nonce = nonce ?? _builder.Nonce,
        EncryptionKeyThumbprint = thumbprint ?? _builder.EncryptionKeyThumbprint,
        ResponseUri = responseUri ?? _builder.ResponseUri,
    };

    [Fact]
    public async Task DeviceAuth_WithMatchingTranscript_Verifies()
    {
        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task DeviceAuth_WithEncryptionKeyThumbprint_Verifies()
    {
        _builder.EncryptionKeyThumbprint = SHA256.HashData([1, 2, 3]);

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("clientId")]
    [InlineData("nonce")]
    [InlineData("responseUri")]
    [InlineData("thumbprint")]
    public async Task AnyTamperedTranscriptInput_FailsDeviceAuth(string input)
    {
        var context = input switch
        {
            "clientId" => Context(clientId: "x509_san_dns:attacker.example"),
            "nonce" => Context(nonce: "replayed-nonce"),
            "responseUri" => Context(responseUri: "https://attacker.example/callback"),
            _ => Context(thumbprint: SHA256.HashData([9, 9, 9])),
        };

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), context);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task WrongDeviceKey_FailsDeviceAuth()
    {
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _builder.DeviceSignerOverride = wrongKey;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task MissingDeviceSigned_IsRejected_ByDefault()
    {
        _builder.IncludeDeviceAuth = false;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }

    [Fact]
    public async Task MissingDeviceSigned_IsAccepted_WhenNotRequired()
    {
        _builder.IncludeDeviceAuth = false;

        var result = await VerifierFor(_builder, new MdocVerifierOptions { RequireDeviceAuth = false })
            .VerifyAsync(Credential(_builder), Context());

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task DeviceMac_IsRejectedAsUnsupported()
    {
        _builder.UseDeviceMac = true;

        var result = await VerifierFor(_builder).VerifyAsync(Credential(_builder), Context());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
        Assert.Contains("deviceMac", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingTranscriptInputs_FailClosed()
    {
        var result = await VerifierFor(_builder).VerifyAsync(
            Credential(_builder), new MdocVerificationContext { ExpectedDocType = MdocTestBuilder.DefaultDocType });

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
        Assert.Contains("session transcript inputs", error.Message, StringComparison.Ordinal);
    }

    public void Dispose() => _builder.Dispose();
}
