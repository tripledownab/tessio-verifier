using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

// SPEC: age verification technical specification 1.1.0, Annex A, A.8 and A.11. The proof shows that an mdoc
// signed by the given issuer key, valid at the wallet's timestamp and bound to the session transcript, holds
// the disclosed values: Longfellow's prover fails when "the mdoc is invalid, or the now time does not satisfy
// the validFrom and validUntil constraints" (longfellow-zk v0.9, lib/circuits/mdoc/mdoc_zk.h). Everything the
// proof does not cover is checked here: which circuit, which docType, how far the timestamp is from now and
// whether the issuer key's certificate chain is trusted. One thing it does not cover cannot be checked: the
// namespace. The circuit proves an issuer signed element with this identifier and value, not where the MSO
// filed it. The library uses the namespace only to require one per presentation. Claims are reported
// under the namespace the presentation states.
public sealed partial class MdocVerifier
{
    private async Task<VerificationResult> VerifyZkAsync(
        ParsedDeviceResponse response, MdocVerificationContext context, IZkProofVerifier zk, CancellationToken ct)
    {
        if (response.ZkDocuments.Count != 1)
        {
            return Failure(MdocErrorCodes.StructureInvalid,
                $"Expected exactly one zero knowledge presentation, found {response.ZkDocuments.Count}.");
        }

        var document = ZkDocumentParser.Parse(response.ZkDocuments[0]);
        if (LongfellowSystemId.Parse(document.ZkSystemId)?.CircuitHash is not { } circuitHash || !zk.AcceptsCircuit(circuitHash))
        {
            return Failure(MdocErrorCodes.ZkCircuitNotAccepted,
                $"The zero knowledge presentation names '{document.ZkSystemId}', which is not an accepted circuit.");
        }

        if (context.ExpectedDocType is { } expected && !string.Equals(document.DocType, expected, StringComparison.Ordinal))
        {
            return Failure(MdocErrorCodes.DocTypeMismatch,
                $"The presentation's docType '{document.DocType}' does not match the requested '{expected}'.");
        }

        if (document.NameSpaces.Count != 1 || document.NameSpaces.Single().Value.Count is < 1 or > 4)
        {
            return Failure(MdocErrorCodes.StructureInvalid,
                "A zero knowledge presentation must disclose one to four items from one namespace.");
        }

        var now = _clock.GetUtcNow();
        if ((now - document.Timestamp).Duration() > _options.ClockSkew)
        {
            return Failure(MdocErrorCodes.ZkTimestampOutOfRange,
                $"The presentation's timestamp {document.TimestampText} is more than {_options.ClockSkew} from now.");
        }

        // SPEC: Annex A, A.6: zero knowledge presentations travel only over the W3C Digital Credentials API,
        // whose session transcript the caller builds (for example with Iso18013AnnexC.BuildSessionTranscript).
        // The OpenID4VP redirect transcript built from ClientId and Nonce would never match the proof.
        if (context.SessionTranscript is not { } transcript)
        {
            return Failure(MdocErrorCodes.DeviceAuthInvalid,
                "The verification context carries no SessionTranscript; a zero knowledge proof cannot be verified without the transcript of the Digital Credentials API request.");
        }

        if (IssuerOfChain(document.MsoX5Chain) is not { } signer)
        {
            return Failure(MdocErrorCodes.IssuerKeyUnresolvable,
                "The presentation's msoX5chain does not start with a certificate holding a P-256 public key.");
        }

        var (trust, trustFailure) = await TrustSeam.ResolveAsync(
            _trustListResolver, signer.Subject, document.MsoX5Chain, ct).ConfigureAwait(false);
        var issuer = IssuerOf(signer.Subject, trust);
        if (!trust.Trusted)
        {
            var error = trustFailure ?? new VerificationError
            {
                Code = MdocErrorCodes.IssuerUntrusted,
                Message = trust.Reason ?? "The document signer does not chain to a trusted IACA root.",
            };
            return VerificationResult.Invalid(error, issuer) with { CredentialType = document.DocType };
        }

        var (nameSpace, items) = document.NameSpaces.Single();
        var verified = await zk.VerifyAsync(new ZkProofRequest
        {
            ZkSystemId = document.ZkSystemId,
            CircuitHash = circuitHash,
            DocType = document.DocType,
            Timestamp = document.TimestampText,
            SessionTranscript = transcript,
            IssuerKeyX = signer.X,
            IssuerKeyY = signer.Y,
            Disclosures = [.. items.Select(i => new ZkDisclosure(nameSpace, i.ElementIdentifier, i.EncodedValue))],
            Proof = document.Proof,
        }, ct).ConfigureAwait(false);

        if (!verified)
        {
            var error = new VerificationError
            {
                Code = MdocErrorCodes.ZkProofInvalid,
                Message = "The zero knowledge proof does not verify for this issuer, transcript, timestamp and disclosure.",
            };
            return VerificationResult.Invalid(error, issuer) with { CredentialType = document.DocType };
        }

        var elements = items.ToDictionary(i => i.ElementIdentifier, i => i.Value, StringComparer.Ordinal);
        return VerificationResult.Valid(new Dictionary<string, object>(StringComparer.Ordinal) { [nameSpace] = elements }, issuer)
            with { CredentialType = document.DocType };
    }

    private sealed record Signer(string Subject, byte[] X, byte[] Y);

    /// <summary>The document signer's subject and P-256 key, or null when the leaf is not such a certificate.</summary>
    private static Signer? IssuerOfChain(ReadOnlyMemory<byte>[] chain)
    {
        try
        {
            using var leaf = DerCertificate.Load(chain[0].ToArray());
            using var key = leaf.GetECDsaPublicKey();
            if (key is null)
            {
                return null;
            }

            var parameters = key.ExportParameters(includePrivateParameters: false);
            return parameters.Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value
                ? new Signer(leaf.Subject, parameters.Q.X!, parameters.Q.Y!)
                : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
