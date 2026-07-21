using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Verifies an mdoc presentation (<c>mso_mdoc</c>, ISO/IEC 18013-5 over OpenID4VP Annex B.2):
/// DeviceResponse decoding, issuerAuth signature via the x5chain Document Signer certificate,
/// MSO validity window, per-item digest checks and IACA trust through
/// <see cref="ITrustListResolver"/>. Structural failures fail fast; policy failures accumulate
/// into <see cref="VerificationResult.Errors"/> with stable codes.
/// </summary>
/// <remarks>
/// Device authentication (the holder's signature over the OpenID4VP session transcript) lands with
/// the session-transcript milestone and is not yet enforced.
/// </remarks>
public sealed class MdocVerifier
{
    /// <summary>The OpenID4VP credential format identifier this verifier accepts.</summary>
    public const string Format = "mso_mdoc";

    private readonly ITrustListResolver _trustListResolver;
    private readonly MdocVerifierOptions _options;
    private readonly TimeProvider _clock;

    /// <summary>Creates a verifier.</summary>
    /// <param name="trustListResolver">
    /// Trust seam deciding whether the Document Signer chain anchors on a trusted IACA root. The
    /// issuer identifier passed to it is the Document Signer certificate subject.
    /// </param>
    /// <param name="options">Policy options; defaults match the SD-JWT verifier.</param>
    /// <param name="clock">Time source for the MSO validity window; system clock when null.</param>
    public MdocVerifier(
        ITrustListResolver trustListResolver,
        MdocVerifierOptions? options = null,
        TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(trustListResolver);
        _trustListResolver = trustListResolver;
        _options = options ?? new MdocVerifierOptions();
        _clock = clock ?? TimeProvider.System;
    }

    /// <summary>Verifies one presented mdoc.</summary>
    public async Task<VerificationResult> VerifyAsync(
        PresentedCredential credential, MdocVerificationContext context, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(credential);
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            return await VerifyCoreAsync(credential, context, ct).ConfigureAwait(false);
        }
        catch (MdocProcessingException e)
        {
            return Failure(e.Code, e.Message);
        }
    }

    private async Task<VerificationResult> VerifyCoreAsync(
        PresentedCredential credential, MdocVerificationContext context, CancellationToken ct)
    {
        if (!string.Equals(credential.Format, Format, StringComparison.Ordinal))
        {
            return Failure(MdocErrorCodes.FormatUnsupported, $"Format '{credential.Format}' is not '{Format}'.");
        }

        var response = DeviceResponseParser.Parse(credential.RawValue);
        if (response.Status != 0)
        {
            return Failure(MdocErrorCodes.StructureInvalid, $"The DeviceResponse status is {response.Status}, not OK (0).");
        }

        if (response.Documents.Count != 1)
        {
            // SPEC: HAIP — one DeviceResponse per DCQL query; multi-document responses are a later milestone.
            return Failure(MdocErrorCodes.StructureInvalid,
                $"Expected exactly one document in the DeviceResponse, found {response.Documents.Count}.");
        }

        var document = response.Documents[0];

        // Structural: issuerAuth signature and Document Signer key (fails fast on error).
        var resolution = IssuerAuthVerifier.Verify(document.IssuerAuth);
        var mso = DeviceResponseParser.ParseMso(document.IssuerAuth);

        // Policy checks accumulate.
        List<VerificationError> errors = [];

        if (context.ExpectedDocType is { } expected && !string.Equals(document.DocType, expected, StringComparison.Ordinal))
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.DocTypeMismatch,
                Message = $"The document's docType '{document.DocType}' does not match the requested '{expected}'.",
            });
        }

        var now = _clock.GetUtcNow();
        if (now + _options.ClockSkew < mso.ValidFrom)
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.CredentialNotYetValid,
                Message = $"The MSO is not valid before {mso.ValidFrom:o}.",
            });
        }

        if (now - _options.ClockSkew >= mso.ValidUntil)
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.CredentialExpired,
                Message = $"The MSO expired at {mso.ValidUntil:o}.",
            });
        }

        errors.AddRange(DigestVerifier.Verify(document, mso));

        var trust = await _trustListResolver.ResolveAsync(resolution.Issuer, resolution.CertificateChain, ct)
            .ConfigureAwait(false);
        if (!trust.Trusted)
        {
            errors.Add(new VerificationError
            {
                Code = MdocErrorCodes.IssuerUntrusted,
                Message = trust.Reason ?? "The Document Signer does not chain to a trusted IACA root.",
            });
        }

        var issuer = new IssuerInfo
        {
            Identifier = resolution.Issuer,
            Trusted = trust.Trusted,
            KeyResolutionMethod = "x5c",
        };

        if (errors.Count > 0)
        {
            return new VerificationResult
            {
                IsValid = false,
                DisclosedClaims = new Dictionary<string, object>(StringComparer.Ordinal),
                Issuer = issuer,
                Errors = errors,
            };
        }

        return new VerificationResult
        {
            IsValid = true,
            DisclosedClaims = BuildClaims(document),
            Issuer = issuer,
            Errors = [],
        };
    }

    /// <summary>Disclosed claims keyed by namespace, each value a map of element name to value.</summary>
    private static Dictionary<string, object> BuildClaims(ParsedDocument document)
    {
        Dictionary<string, object> claims = new(StringComparer.Ordinal);
        foreach (var (ns, items) in document.NameSpaces)
        {
            Dictionary<string, object?> elements = new(StringComparer.Ordinal);
            foreach (var item in items)
            {
                elements[item.ElementIdentifier] = item.ElementValue;
            }

            claims[ns] = elements;
        }

        return claims;
    }

    private static VerificationResult Failure(string code, string message) => new()
    {
        IsValid = false,
        DisclosedClaims = new Dictionary<string, object>(StringComparer.Ordinal),
        Issuer = new IssuerInfo { Identifier = "unknown", Trusted = false, KeyResolutionMethod = "x5c" },
        Errors = [new VerificationError { Code = code, Message = message }],
    };
}
