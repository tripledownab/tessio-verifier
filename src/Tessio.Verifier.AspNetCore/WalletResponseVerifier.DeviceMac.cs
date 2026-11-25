// What belongs in this file: finding the reader key a deviceMac is checked with, for each route. The check itself
// is Core.Mdoc's (MdocMacKeySource, DeviceMacVerifier).
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

public sealed partial class WalletResponseVerifier
{
    /// <summary>
    /// The reader key of a redirect session, for an encrypted response carrying an mdoc. Null when the request
    /// published no key, the response holds no mdoc, or the key is no longer held.
    /// </summary>
    /// <remarks>
    /// Copied out of the store once, before anything is verified, so a key the store evicts while a check waits on
    /// the network is not disposed under it. A key already gone means the request has expired; its deviceMac is
    /// refused as having no key, and a deviceSignature does not need one. Nothing here throws: a deviceSignature
    /// response looks the key up too, and must verify as it did before deviceMac was accepted.
    /// </remarks>
    private MdocMacKeySource? MacKeysFor(VerificationSession session, ParsedWalletResponse response)
    {
        // The response first: a wallet's error carries no credentials, and its request must not be read before
        // VerifyAgainstAsync has answered it, since a host may have lost the request by then. Encrypted only, as on
        // the Digital Credentials API route, although a cleartext request can name a key in client_metadata.
        if (!HasMdoc(response)
            || !RequestParameters.AsksForEncryptedResponse(session.Request)
            || RequestParameters.TryGetEncryptionKeyId(session.Request) is not { } kid)
        {
            return null;
        }

        try
        {
            return MacKeysFrom(_encryptionKeys.Get(kid)?.DecryptionKey);
        }
        catch (InvalidOperationException)
        {
            // Three ways to get here, all meaning no usable key rather than a failed request: a stored salt that
            // derives another key (ResponseEncryptionKeyStore.Get); a ResponseKeyGenerationUnavailableException, a
            // subtype, when the salt's master generation is not held; and an ObjectDisposedException, also a subtype,
            // when the store evicted the key between the lookup and the copy.
            return null;
        }
    }

    /// <summary>
    /// A copy of <paramref name="key"/> as an mdoc reader key, or null when it is not a P-256 key whose private half
    /// can be read. The response keys this library makes are readable; a host passing another kind gets deviceMac
    /// refused.
    /// </summary>
    private static MdocMacKeySource? MacKeysFrom(SecurityKey? key)
    {
        if (key is not ECDsaSecurityKey { ECDsa: { } ecdsa })
        {
            return null;
        }

        try
        {
            var parameters = ecdsa.ExportParameters(includePrivateParameters: true);
            try
            {
                return MdocMacKeySource.FromPrivateKey(parameters);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(parameters.D);
            }
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            return null;
        }
    }

    private static bool HasMdoc(ParsedWalletResponse response) =>
        response.Credentials.Any(static c => string.Equals(c.Format, MdocVerifier.Format, StringComparison.Ordinal));
}
