using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Cross-implementation device authentication: the deviceSigned structure in this fixture was built
/// and COSE-signed by the OpenWallet Foundation wallet-framework-dotnet over the OpenID4VP Annex
/// B.2.6.1 session transcript. Our verifier reconstructs the transcript and
/// DeviceAuthenticationBytes independently; agreement here is interop, not self-confirmation.
/// </summary>
public sealed class WalletFrameworkInteropTests
{
    private static X509Certificate2 Iaca() =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(WalletFrameworkInteropVectors.IacaCertificate);
#else
        new(WalletFrameworkInteropVectors.IacaCertificate);
#endif

    [Fact]
    public async Task ExternallyDeviceSignedPresentation_Verifies_EndToEnd()
    {
        using var iaca = Iaca();
        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [WalletFrameworkInteropVectors.DsSubject], source: "wallet-framework-interop", trustAnchors: [iaca]));

        var result = await verifier.VerifyAsync(
            new PresentedCredential
            {
                Format = MdocVerifier.Format,
                RawValue = WalletFrameworkInteropVectors.DeviceResponse,
            },
            new MdocVerificationContext
            {
                ExpectedDocType = WalletFrameworkInteropVectors.DocType,
                ClientId = WalletFrameworkInteropVectors.ClientId,
                Nonce = WalletFrameworkInteropVectors.Nonce,
                EncryptionKeyThumbprint = null,
                ResponseUri = WalletFrameworkInteropVectors.ResponseUri,
            });

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
        Assert.True(result.Issuer.Trusted);

        var elements = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims["org.iso.18013.5.1"]);
        Assert.Equal("Interop", elements["family_name"]);
        Assert.Equal(true, elements["age_over_18"]);
    }

    [Fact]
    public async Task TamperedNonce_FailsTheirDeviceSignature()
    {
        using var iaca = Iaca();
        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [WalletFrameworkInteropVectors.DsSubject], source: "wallet-framework-interop", trustAnchors: [iaca]));

        var result = await verifier.VerifyAsync(
            new PresentedCredential
            {
                Format = MdocVerifier.Format,
                RawValue = WalletFrameworkInteropVectors.DeviceResponse,
            },
            new MdocVerificationContext
            {
                ExpectedDocType = WalletFrameworkInteropVectors.DocType,
                ClientId = WalletFrameworkInteropVectors.ClientId,
                Nonce = "a-different-nonce",
                EncryptionKeyThumbprint = null,
                ResponseUri = WalletFrameworkInteropVectors.ResponseUri,
            });

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Code == MdocErrorCodes.DeviceAuthInvalid);
    }
}
