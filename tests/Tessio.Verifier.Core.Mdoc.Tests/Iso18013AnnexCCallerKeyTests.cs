// What belongs in this file: Annex C requests built around a response key the caller supplies, as a verifier
// that derives its keys does. The minted-key path and opening are in Iso18013AnnexCFlowTests, readerAuth's
// wiring in SignedDeviceRequestTests.
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Core.Mdoc.Tests;

public sealed class Iso18013AnnexCCallerKeyTests : IDisposable
{
    private const string Origin = "https://verifier.example.com";

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    private static Iso18013AnnexCRequest Request(ECDiffieHellman key, ZkRequest? zkRequest = null) =>
        Iso18013AnnexC.CreateRequest(AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], zkRequest, key);

    [Fact]
    public void The_request_advertises_the_callers_key_and_hands_back_its_private_half()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        var request = Request(key);

        var expected = key.ExportParameters(includePrivateParameters: true);
        var advertised = EncryptionInfo.ReadRecipientKey(request.EncryptionInfo);
        Assert.Equal(expected.Q.X, advertised.Q.X);
        Assert.Equal(expected.Q.Y, advertised.Q.Y);
        using var handedBack = ECDiffieHellman.Create();
        handedBack.ImportPkcs8PrivateKey(request.ResponseKeyPkcs8, out _);
        Assert.Equal(expected.D, handedBack.ExportParameters(includePrivateParameters: true).D);
    }

    [Fact]
    public void A_response_opens_with_the_same_key_made_again()
    {
        // What a verifier that derives its keys relies on: another instance or this one after a restart makes the
        // key again from what it stored, and that key opens the answer to the first request.
        var parameters = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256).ExportParameters(includePrivateParameters: true);
        Iso18013AnnexCRequest request;
        using (var first = ECDiffieHellman.Create(parameters))
        {
            request = Request(first);
        }

        var deviceResponse = "stand-in DeviceResponse bytes"u8.ToArray();
        var sealed_ = Iso18013AnnexC.SealResponse(deviceResponse, request.EncryptionInfo, Origin);

        using var again = ECDiffieHellman.Create(parameters);
        var opened = Iso18013AnnexC.OpenResponse(sealed_, again.ExportPkcs8PrivateKey(), request.EncryptionInfo, Origin);
        Assert.Equal(deviceResponse, opened.DeviceResponse);
    }

    [Fact]
    public void Each_request_still_gets_its_own_nonce()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        Assert.NotEqual(Request(key).EncryptionInfo, Request(key).EncryptionInfo);
    }

    [Fact]
    public void The_callers_key_is_left_to_the_caller()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        _ = Request(key);

        // A disposed key throws here.
        Assert.NotNull(key.ExportParameters(includePrivateParameters: true).D);
    }

    [Fact]
    public void A_key_on_another_curve_is_refused()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);

        Assert.Throws<ArgumentException>("responseKey", () => Request(key));
    }

    [Fact]
    public void A_key_on_a_curve_the_size_of_P256_is_refused()
    {
        // Its points have P-256's size, so only the curve's name tells it apart: it would be encoded and
        // advertised as a P-256 key that never opens an answer.
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.brainpoolP256r1);

        Assert.Throws<ArgumentException>("responseKey", () => Request(key));
    }

    [Fact]
    public void A_P256_key_given_by_explicit_parameters_is_refused()
    {
        using var named = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var key = ECDiffieHellman.Create(named.ExportExplicitParameters(includePrivateParameters: true));

        Assert.Throws<ArgumentException>("responseKey", () => Request(key));
    }

    [Fact]
    public void A_key_that_exports_no_private_half_is_refused_even_when_the_export_does_not_throw()
    {
        using var key = new ExportsNoPrivateHalf();

        Assert.Throws<ArgumentException>("responseKey", () => Request(key));
    }

    [Fact]
    public void A_key_without_its_private_half_is_refused()
    {
        using var full = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var publicOnly = ECDiffieHellman.Create(full.ExportParameters(includePrivateParameters: false));

        Assert.Throws<ArgumentException>("responseKey", () => Request(publicOnly));
    }

    [Fact]
    public void A_null_key_is_refused_rather_than_replaced_with_a_minted_one()
    {
        Assert.Throws<ArgumentNullException>("responseKey", () => Request(null!));
        Assert.Throws<ArgumentNullException>("responseKey", () => Iso18013AnnexC.CreateSignedRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], Origin, ReaderKey(), null, null, null!));
    }

    [Fact]
    public void The_zero_knowledge_request_is_asked_as_with_a_minted_key()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var zk = new ZkRequest(AvZkVectors.RequestedSystemIds) { Required = true };

        // An unsigned DeviceRequest does not depend on the key, so the two must match byte for byte.
        Assert.Equal(
            Iso18013AnnexC.CreateRequest(AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], zk).DeviceRequest,
            Request(key, zk).DeviceRequest);
    }

    [Fact]
    public void A_signed_request_advertises_the_callers_key_and_signs_over_it()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        var request = Iso18013AnnexC.CreateSignedRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], Origin, ReaderKey(), null, null, key);

        Assert.Equal(key.ExportParameters(false).Q.X, EncryptionInfo.ReadRecipientKey(request.EncryptionInfo).Q.X);
        var (itemsRequest, encodedReaderAuth) = DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest);
        var readerAuth = CoseMessage.DecodeSign1(encodedReaderAuth!);
        var transcript = SessionTranscriptBuilder.BuildForIso18013AnnexC(request.EncryptionInfo, Origin);
        using var leafKey = _certificates.Reader.GetECDsaPublicKey()!;
        Assert.True(readerAuth.VerifyDetached(leafKey, ReaderAuthentication.BuildBytes(transcript, itemsRequest)));
    }

    [Fact]
    public void A_signed_request_with_a_callers_key_asks_the_zero_knowledge_request_too()
    {
        using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var zk = new ZkRequest(AvZkVectors.RequestedSystemIds) { Required = true };

        var withKey = Iso18013AnnexC.CreateSignedRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], Origin, ReaderKey(), null, zk, key);
        var minted = Iso18013AnnexC.CreateSignedRequest(
            AvZkVectors.DocType, AvZkVectors.DocType, ["age_over_18"], Origin, ReaderKey(), null, zk);

        // The signature differs with the transcript; what is asked must not.
        Assert.Equal(
            DeviceRequestReader.ReadSingleDocRequest(minted.DeviceRequest).ItemsRequest,
            DeviceRequestReader.ReadSingleDocRequest(withKey.DeviceRequest).ItemsRequest);
    }

    private MdocReaderKey ReaderKey() => new(_certificates.ReaderKey, [_certificates.Reader]);

    /// <summary>A P-256 key whose export says it succeeded but carries no private half.</summary>
    private sealed class ExportsNoPrivateHalf : ECDiffieHellman
    {
        private readonly ECDiffieHellman _inner = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

        public override ECDiffieHellmanPublicKey PublicKey => _inner.PublicKey;

        public override ECParameters ExportParameters(bool includePrivateParameters) =>
            _inner.ExportParameters(includePrivateParameters: false);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
