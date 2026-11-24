// What belongs in this file: turning the reader's private key into the key a deviceMac is checked with,
// and nothing that lets the private key or the raw key agreement out.
using System.Security.Cryptography;
using System.Text;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// The reader's side of MAC-based mdoc device authentication: holds the reader's P-256 private key and
/// derives, for one device key and one session transcript, the key a <c>deviceMac</c> is checked with
/// (EMacKey). Pass one in <see cref="MdocVerificationContext.MacKeySource"/> to accept <c>deviceMac</c>;
/// without one it is refused.
/// </summary>
/// <remarks>
/// <para>
/// It has no public member that derives anything, and it never hands out the private key or the raw key
/// agreement: only the mdoc verifier derives with it. The raw agreement is withheld on purpose. Given any
/// public key it is the shared secret with that key, so handing it out would let a caller pass the
/// ephemeral key of a response encrypted to the same key pair and open that response. EMacKey has been through HKDF with the transcript and its
/// own label, and opens nothing.
/// </para>
/// <para>
/// Under OpenID4VP the reader key is the one the request published in <c>client_metadata.jwks</c> and the
/// response was encrypted to. OpenID4VP 1.0 section 5.1 lists, beside encryption, keys "where the Wallet
/// will require the public key of the Verifier to generate a Verifiable Presentation", and Appendix B.2.5
/// says the DeviceResponse "contains a signature or MAC over the SessionTranscript". That a MAC is keyed
/// with that key is this library's reading; no text it can cite says so in those words.
/// </para>
/// <para>
/// The key is copied in, so the caller may dispose its own copy at once. Dispose this when the
/// verification it was made for has finished.
/// </para>
/// </remarks>
// SPEC: ISO/IEC 18013-5 section 9.1.3.5 as OpenID4VP 1.0 Appendix B.2.2 cites it; quoted from the second
// edition working draft (WG 10, 2025-09-14), clause 12.4.5, as the published edition is not to hand: the
// reader performs ECKA-DH with "EReaderKey.Priv and SDeviceKey.Pub", and "EMacKey shall be derived using
// HKDF as defined in RFC 5869" with "Hash: SHA-256", "IKM: ZAB", "salt: SHA-256(SessionTranscriptBytes)",
// "info: “EMacKey”" and "L: 32 octets". Its NOTE: the method works only when both keys "use the same
// curve".
public sealed class MdocMacKeySource : IDisposable
{
    private static readonly byte[] Info = Encoding.UTF8.GetBytes("EMacKey");

    private readonly ECDiffieHellman _readerKey;

    private MdocMacKeySource(ECDiffieHellman readerKey) => _readerKey = readerKey;

    /// <summary>A source holding a copy of the reader's private key.</summary>
    /// <param name="readerPrivateKey">The reader key on P-256, with its private scalar.</param>
    /// <exception cref="ArgumentException">The key is not on P-256, has no private scalar or cannot be imported.</exception>
    public static MdocMacKeySource FromPrivateKey(ECParameters readerPrivateKey)
    {
        if (!IsP256(readerPrivateKey.Curve))
        {
            throw new ArgumentException("The reader key must be on P-256.", nameof(readerPrivateKey));
        }

        if (readerPrivateKey.D is null)
        {
            throw new ArgumentException("The reader key has no private scalar.", nameof(readerPrivateKey));
        }

        var key = ECDiffieHellman.Create();
        try
        {
            key.ImportParameters(readerPrivateKey);
        }
        catch (CryptographicException e)
        {
            key.Dispose();
            throw new ArgumentException($"The reader key cannot be imported: {e.Message}", nameof(readerPrivateKey), e);
        }

        return new MdocMacKeySource(key);
    }

    /// <summary>The EMacKey for one device key and one transcript.</summary>
    /// <param name="devicePublicKey">The device key the MSO binds.</param>
    /// <param name="sessionTranscriptBytes">The tag-24 wrapped transcript, <c>#6.24(bstr .cbor SessionTranscript)</c>.</param>
    /// <exception cref="CryptographicException">The device key is not on P-256.</exception>
    /// <exception cref="ObjectDisposedException">This source has been disposed.</exception>
    internal byte[] DeriveEMacKey(ECParameters devicePublicKey, byte[] sessionTranscriptBytes)
    {
        if (!IsP256(devicePublicKey.Curve))
        {
            throw new CryptographicException("The device key is not on P-256, the only curve a deviceMac is accepted on.");
        }

        using var device = ECDiffieHellman.Create(devicePublicKey);
        var zab = _readerKey.DeriveRawSecretAgreement(device.PublicKey);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, zab, 32, SHA256.HashData(sessionTranscriptBytes), Info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(zab);
        }
    }

    /// <inheritdoc />
    public void Dispose() => _readerKey.Dispose();

    // P-256 only. OpenID4VP 1.0 Appendix B.2.2, Table 2 gives -65537 to "HMAC 256/256 using ECDH with Curve
    // P-256", and the response encryption key a request publishes is on P-256, so with the NOTE above a
    // device key on any other curve cannot have been used with it.
    private static bool IsP256(ECCurve curve) =>
        curve.IsNamed && curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value;
}
