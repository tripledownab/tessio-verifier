using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// What belongs here: that an mdoc failure message is one line when it quotes a value the presenter
/// chose. The docType is one: the mismatch message names it as the document declares it.
/// </summary>
public sealed class OneLineMessageTests : IDisposable
{
    // Line feed, carriage return, NEL (a C1 control), and the two Unicode line separators.
    private const string Hostile = "Evil\nINFO: forged\r\u0085next\u2028and\u2029end";

    private readonly MdocTestBuilder _builder = new() { DocType = "org.example." + Hostile };

    [Fact]
    public async Task ADocTypeMismatchQuotingAHostileDocType_IsOneLine()
    {
        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [_builder.DsCertificate.Subject], source: "mdoc-test", trustAnchors: [_builder.IacaCertificate]));
        var context = new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            ClientId = _builder.ClientId,
            Nonce = _builder.Nonce,
            EncryptionKeyThumbprint = _builder.EncryptionKeyThumbprint,
            ResponseUri = _builder.ResponseUri,
        };

        var result = await verifier.VerifyAsync(
            new PresentedCredential { Format = MdocVerifier.Format, RawValue = _builder.BuildBase64Url() }, context);

        Assert.False(result.IsValid);
        var mismatch = Assert.Single(result.Errors, e => e.Code == MdocErrorCodes.DocTypeMismatch);
        Assert.Contains("Evil" + "\uFFFD" + "INFO: forged", mismatch.Message, StringComparison.Ordinal);
        foreach (var error in result.Errors)
        {
            Assert.DoesNotContain(error.Message, c => char.IsControl(c) || c is '\u2028' or '\u2029');
        }
    }

    public void Dispose() => _builder.Dispose();
}
