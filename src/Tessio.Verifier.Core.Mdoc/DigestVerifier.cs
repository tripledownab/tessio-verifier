using System.Security.Cryptography;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Checks every disclosed IssuerSignedItem against the MSO's <c>valueDigests</c>: the digest of the
/// item's transported bytes must appear under its namespace and digestID. This is the mdoc analogue
/// of SD-JWT disclosure hashing — it is what makes the issuer's signature cover selectively
/// disclosed values.
/// </summary>
// SPEC: ISO/IEC 18013-5 §9.1.2.4 (digest computation), §9.3.1 (verification procedure).
internal static class DigestVerifier
{
    public static List<VerificationError> Verify(ParsedDocument document, MobileSecurityObject mso)
    {
        List<VerificationError> errors = [];

        if (!string.Equals(document.DocType, mso.DocType, StringComparison.Ordinal))
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.MsoInvalid,
                Message = $"The document's docType '{document.DocType}' does not match the MSO's '{mso.DocType}'.",
            });
            return errors;
        }

        if (HashFor(mso.DigestAlgorithm) is not { } hash)
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.MsoInvalid,
                Message = $"The MSO digest algorithm '{mso.DigestAlgorithm}' is not supported.",
            });
            return errors;
        }

        foreach (var (ns, items) in document.NameSpaces)
        {
            mso.ValueDigests.TryGetValue(ns, out var nsDigests);
            foreach (var item in items)
            {
                if (nsDigests is null || !nsDigests.TryGetValue(item.DigestId, out var expected))
                {
                    errors.Add(new VerificationError
                    {
                        Code = MdocErrorCodes.DigestMismatch,
                        Message = $"Item '{item.ElementIdentifier}' (digestID {item.DigestId}) in '{ns}' has no digest in the MSO.",
                    });
                    continue;
                }

                if (!hash(item.EncodedItemBytes).AsSpan().SequenceEqual(expected))
                {
                    errors.Add(new VerificationError
                    {
                        Code = MdocErrorCodes.DigestMismatch,
                        Message = $"Item '{item.ElementIdentifier}' (digestID {item.DigestId}) in '{ns}' does not match its MSO digest.",
                    });
                }
            }
        }

        return errors;
    }

    private static Func<byte[], byte[]>? HashFor(string digestAlgorithm) => digestAlgorithm switch
    {
        "SHA-256" => SHA256.HashData,
        "SHA-384" => SHA384.HashData,
        "SHA-512" => SHA512.HashData,
        _ => null,
    };
}
