using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>The outcome of issuer signing-key resolution.</summary>
internal sealed record IssuerKeyResolution
{
    public required IReadOnlyList<SecurityKey> Keys { get; init; }

    /// <summary>"x5c" or "jwt-vc-issuer-metadata" (the contract's canonical values).</summary>
    public required string Method { get; init; }

    /// <summary>Issuer identifier: the <c>iss</c> claim, or the end-entity subject when iss is absent.</summary>
    public required string Issuer { get; init; }

    /// <summary>DER certificate chain from <c>x5c</c>; empty for metadata resolution.</summary>
    public required ReadOnlyMemory<byte>[] CertificateChain { get; init; }
}

/// <summary>
/// Resolves the issuer's signing key via the two SD-JWT VC mechanisms: the X.509 chain in the
/// <c>x5c</c> JOSE header, or JWT VC Issuer Metadata fetched from the <c>iss</c> HTTPS URI.
/// </summary>
// SPEC: draft-ietf-oauth-sd-jwt-vc §2.5 (key resolution) and §3 (JWT VC Issuer Metadata).
internal sealed class IssuerKeyResolver
{
    /// <summary>id-ce-subjectAltName, RFC 5280 section 4.2.1.6.</summary>
    /// <remarks>
    /// Matched as an OID rather than as a parsed extension type because this value decides whether a
    /// certificate asserts any name at all, and that answer must not depend on whether a given runtime
    /// chose to parse the extension. See <c>CertificateMatchesIssuer</c>.
    /// </remarks>
    private const string SubjectAltNameOid = "2.5.29.17";

    private readonly HttpClient _httpClient;

    public IssuerKeyResolver(HttpClient httpClient) => _httpClient = httpClient;

    public async Task<IssuerKeyResolution> ResolveAsync(JsonWebToken issuerJwt, CancellationToken ct)
    {
        var iss = issuerJwt.TryGetClaim("iss", out var issClaim) ? issClaim.Value : null;

        var chain = ReadX5cHeader(issuerJwt);
        if (chain is not null)
        {
            return ResolveFromX5c(chain, iss);
        }

        if (iss is null)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable,
                "The credential carries neither an x5c header nor an iss claim; no key resolution mechanism applies.");
        }

        return await ResolveFromMetadataAsync(iss, ct).ConfigureAwait(false);
    }

    // ---- X.509 (x5c) --------------------------------------------------------------------------

    private static List<X509Certificate2>? ReadX5cHeader(JsonWebToken issuerJwt)
    {
        // SPEC: RFC 7515 §4.1.6 — x5c is an array of base64 (standard, NOT base64url) DER certificates,
        // the first entry being the end-entity (signing) certificate.
        using var header = JsonDocument.Parse(Base64UrlEncoder.Decode(issuerJwt.EncodedHeader));
        if (!header.RootElement.TryGetProperty("x5c", out var x5c))
        {
            return null;
        }

        try
        {
            if (x5c.ValueKind != JsonValueKind.Array || x5c.GetArrayLength() == 0)
            {
                throw new FormatException("x5c is not a non-empty array.");
            }

            return x5c.EnumerateArray()
                .Select(entry => LoadCertificate(Convert.FromBase64String(entry.GetString()
                    ?? throw new FormatException("x5c entry is not a string."))))
                .ToList();
        }
        catch (Exception e) when (e is FormatException or InvalidOperationException or CryptographicException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable, "The x5c header is not a valid base64 DER certificate chain.");
        }
    }

    private static X509Certificate2 LoadCertificate(byte[] der) =>
#if NET9_0_OR_GREATER
        X509CertificateLoader.LoadCertificate(der);
#else
        new(der);
#endif

    private static IssuerKeyResolution ResolveFromX5c(List<X509Certificate2> certificates, string? iss)
    {
        var leaf = certificates[0];

        // SPEC: draft-ietf-oauth-sd-jwt-vc §2.5 — the end-entity certificate identifies the issuer.
        // When iss is also present, require it to be consistent with the certificate (SAN DNS matching
        // the iss host, or the iss URI appearing as a SAN entry) so an unrelated certificate cannot
        // vouch for an arbitrary iss value.
        if (iss is not null && !CertificateMatchesIssuer(leaf, iss))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerCertificateMismatch,
                "The iss claim does not match any subject alternative name of the end-entity certificate.");
        }

        // Extract the typed public key: X509SecurityKey does not support ECDSA certificates in
        // Microsoft.IdentityModel's crypto providers, and ES256 is the norm for EUDI issuers.
        // A structurally valid certificate can still carry key bits the platform crypto layer
        // rejects (e.g. an EC point off the curve); those throw OS-specific CryptographicException
        // subtypes and must map to a typed verification error.
        SecurityKey leafKey;
        try
        {
            leafKey = leaf.GetECDsaPublicKey() is { } ecdsa
                ? new ECDsaSecurityKey(ecdsa)
                : leaf.GetRSAPublicKey() is { } rsa
                    ? new RsaSecurityKey(rsa)
                    : throw new SdJwtProcessingException(
                        ErrorCodes.IssuerKeyUnresolvable, "The end-entity certificate carries neither an EC nor an RSA public key.");
        }
        catch (CryptographicException e)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable, $"The end-entity certificate's key is unusable: {e.Message}");
        }

        return new IssuerKeyResolution
        {
            Keys = [leafKey],
            Method = SdJwtConstants.KeyResolutionX5c,
            Issuer = iss ?? leaf.Subject,
            CertificateChain = certificates.Select(c => new ReadOnlyMemory<byte>(c.RawData)).ToArray(),
        };
    }

    private static bool CertificateMatchesIssuer(X509Certificate2 certificate, string iss)
    {
        var issHost = Uri.TryCreate(iss, UriKind.Absolute, out var issUri) ? issUri.Host : null;
        var sanExtensions = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().ToList();

        // A certificate that asserts NO names cannot contradict iss, so there is nothing to check.
        // SPEC: draft-ietf-oauth-sd-jwt-vc-10 section 3.5 says that with an x5c header "the Issuer of the
        // Verifiable Credential is the subject of the end-entity certificate", and section 3.2.2.2 makes
        // iss OPTIONAL precisely because the certificate conveys the issuer. Requiring a SAN match
        // unconditionally invents a requirement the specification does not make. (Later drafts renumber
        // these to 2.5 and 2.2.2.3; the text is unchanged. This file cites the -10 numbering throughout.)
        //
        // It is not hypothetical. The EUDI Wallet Reference Implementation's PID issuer signs SD-JWT VC
        // PIDs with a leaf carrying NO subjectAltName, while its iss is https://issuer-backend.eudiw.dev.
        // Every such credential was rejected as issuer_certificate_mismatch, which is the Commission's own
        // reference PID refused by us. Found 2026-09-20 from a real presentation, not from review.
        //
        // NO subjectAltName, not "no extensions": that leaf carries six others. An earlier note here said
        // it had none, from misreading `openssl x509 -ext subjectAltName`, whose "No extensions in
        // certificate" means none MATCHING, not none at all. The distinction matters because one of the
        // six is an ISSUER Alternative Name, OID 2.5.29.18, one digit from the OID below and carrying an
        // unrelated URL. Widening the fallback to "any name-ish extension" would pull that URL into
        // issuer matching.
        //
        // The check is KEPT where it has something to compare, so a certificate naming one host cannot
        // vouch for an iss naming another. Authenticity still rests on the chain reaching a configured
        // trust anchor, which is the control that was doing the real work all along.
        //
        // ASKED BY OID, not by the CLR type above, and the difference is a security one. This branch is
        // the only place that turns "we found nothing" into "accept". X509SubjectAlternativeNameExtension
        // is a PARSED view, so a runtime that returned a plain X509Extension for this OID would make the
        // typed list empty on a certificate that does assert names, and keying on that would accept a
        // certificate naming somebody else. The OID is present or it is not, on every platform. When the
        // extension exists but the runtime did not parse it, the loop below finds no names and the format
        // fallback finds no match, so the answer is refusal. Wrong in the safe direction.
        if (!certificate.Extensions.Any(e => string.Equals(e.Oid?.Value, SubjectAltNameOid, StringComparison.Ordinal)))
        {
            return true;
        }

        foreach (var san in sanExtensions)
        {
            foreach (var dns in san.EnumerateDnsNames())
            {
                if (string.Equals(dns, issHost ?? iss, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }

        // SAN uniformResourceIdentifier entries are not enumerable via the platform API, so fall back to
        // the formatted extension text, which includes URI entries on all platforms.
        //
        // ENTRY BY ENTRY, NEVER A SUBSTRING. This was `Format(false).Contains(iss)`, and a substring test
        // over a URI matches any longer name that starts with it: a SAN of
        // `URI:https://issuer.example.attacker.test/` satisfies `iss = https://issuer.example`. Registering
        // a lookalike domain was the whole attack. Verified against the platform's own formatter rather
        // than reasoned about, 2026-09-20.
        return sanExtensions.SelectMany(san => SplitFormattedEntries(san.Format(false)))
            .Any(entry => IsUriEntryFor(entry, iss));
    }

    /// <summary>Splits the platform's formatted SAN text into one string per entry.</summary>
    /// <remarks>
    /// Separators differ by platform, so both a comma and a newline end an entry. Splitting too eagerly
    /// is safe here: an over-split entry fails to match and the answer is refusal.
    /// </remarks>
    private static string[] SplitFormattedEntries(string formatted) =>
        formatted.Split([',', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Whether one formatted SAN entry is a URI naming exactly <paramref name="iss"/>.</summary>
    /// <remarks>
    /// Compared as URIs when both parse, so that a trailing slash is not a mismatch, and as exact strings
    /// otherwise. Never as a prefix or a substring.
    /// </remarks>
    private static bool IsUriEntryFor(string entry, string iss)
    {
        const string UriLabel = "URI:";
        if (!entry.StartsWith(UriLabel, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var value = entry[UriLabel.Length..].Trim();
        if (Uri.TryCreate(value, UriKind.Absolute, out var entryUri)
            && Uri.TryCreate(iss, UriKind.Absolute, out var issAsUri))
        {
            return Uri.Compare(
                entryUri, issAsUri, UriComponents.AbsoluteUri, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0;
        }

        return string.Equals(value, iss, StringComparison.OrdinalIgnoreCase);
    }

    // ---- JWT VC Issuer Metadata ---------------------------------------------------------------

    private async Task<IssuerKeyResolution> ResolveFromMetadataAsync(string iss, CancellationToken ct)
    {
        if (!Uri.TryCreate(iss, UriKind.Absolute, out var issUri) || issUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable,
                "The iss claim is not an HTTPS URI; JWT VC Issuer Metadata resolution requires one.");
        }

        var metadataUri = BuildMetadataUri(issUri);
        var metadata = await FetchJsonAsync(metadataUri, ct).ConfigureAwait(false);

        // SPEC: draft-ietf-oauth-sd-jwt-vc §3.3 — the metadata's issuer MUST be identical to iss.
        if (!metadata.TryGetProperty("issuer", out var issuerProp)
            || issuerProp.ValueKind != JsonValueKind.String
            || !string.Equals(issuerProp.GetString(), iss, StringComparison.Ordinal))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "JWT VC Issuer Metadata 'issuer' does not match the credential's iss.");
        }

        JsonElement jwks;
        if (metadata.TryGetProperty("jwks", out var inlineJwks))
        {
            jwks = inlineJwks;
        }
        else if (metadata.TryGetProperty("jwks_uri", out var jwksUriProp)
                 && jwksUriProp.ValueKind == JsonValueKind.String
                 && Uri.TryCreate(jwksUriProp.GetString(), UriKind.Absolute, out var jwksUri)
                 && jwksUri.Scheme == Uri.UriSchemeHttps)
        {
            jwks = await FetchJsonAsync(jwksUri, ct).ConfigureAwait(false);
        }
        else
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "JWT VC Issuer Metadata carries neither 'jwks' nor a valid https 'jwks_uri'.");
        }

        var keys = new JsonWebKeySet(jwks.GetRawText()).GetSigningKeys().ToList();
        if (keys.Count == 0)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerMetadataInvalid, "The issuer's JWK Set contains no usable signing keys.");
        }

        return new IssuerKeyResolution
        {
            Keys = keys,
            Method = SdJwtConstants.KeyResolutionMetadata,
            Issuer = iss,
            CertificateChain = [],
        };
    }

    // SPEC: draft-ietf-oauth-sd-jwt-vc §3 — insert "/.well-known/jwt-vc-issuer" between the host
    // component and the path component of iss; strip any terminating '/' first.
    internal static Uri BuildMetadataUri(Uri issUri)
    {
        var path = issUri.AbsolutePath.TrimEnd('/');
        return new Uri($"{issUri.Scheme}://{issUri.Authority}{SdJwtConstants.WellKnownSegment}{path}");
    }

    private async Task<JsonElement> FetchJsonAsync(Uri uri, CancellationToken ct)
    {
        try
        {
            using var response = await _httpClient.GetAsync(uri, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            return document.RootElement.Clone();
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or TaskCanceledException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.IssuerKeyUnresolvable, $"Fetching issuer metadata from '{uri}' failed: {e.Message}");
        }
    }
}
