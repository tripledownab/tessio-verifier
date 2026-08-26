using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// The mock wallet answering an ISO/IEC 18013-7 Annex C request end to end: request pair, sealed
/// response, decryption, and full mdoc verification with device auth over the Annex C transcript.
/// This is the offline stand-in for a Digital Credentials API wallet, so a consumer's integration
/// tests and the round trip against a real one check the same seams.
/// </summary>
public sealed class AnnexCMockWalletTests
{
    private const string AvDocType = "eu.europa.ec.av.1";
    private const string Origin = "https://verifier.example.com";

    [Fact]
    public async Task A_mock_annex_c_answer_verifies_through_the_full_mdoc_pipeline()
    {
        using var wallet = new MockWalletResponses();
        var request = Iso18013AnnexC.CreateRequest(AvDocType, AvDocType, ["age_over_18"]);

        var encrypted = wallet.CreateAnnexCEncryptedResponse(
            request.EncryptionInfo, Origin,
            claimValues: new Dictionary<string, object> { ["age_over_18"] = true });

        var opened = Iso18013AnnexC.OpenResponse(
            Base64UrlEncoder.DecodeBytes(encrypted), request.ResponseKeyPkcs8, request.EncryptionInfo, Origin);

        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [wallet.MdocIssuerId], source: "annex-c-test", trustAnchors: [wallet.MdocIacaCertificate]));
        var result = await verifier.VerifyAsync(
            new PresentedCredential
            {
                Format = MdocVerifier.Format,
                RawValue = Base64UrlEncoder.Encode(opened.DeviceResponse),
            },
            new MdocVerificationContext
            {
                ExpectedDocType = AvDocType,
                SessionTranscript = opened.EncryptionSessionTranscript,
            });

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[AvDocType]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Fact]
    public void A_mock_annex_c_answer_for_another_origin_does_not_open()
    {
        using var wallet = new MockWalletResponses();
        var request = Iso18013AnnexC.CreateRequest(AvDocType, AvDocType, ["age_over_18"]);

        var encrypted = wallet.CreateAnnexCEncryptedResponse(request.EncryptionInfo, "https://evil.example.com");

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => Iso18013AnnexC.OpenResponse(
            Base64UrlEncoder.DecodeBytes(encrypted), request.ResponseKeyPkcs8, request.EncryptionInfo, Origin));
    }
}
