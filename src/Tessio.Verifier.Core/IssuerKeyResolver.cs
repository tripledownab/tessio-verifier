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
        SecurityKey leafKey = leaf.GetECDsaPublicKey() is { } ecdsa
            ? new ECDsaSecurityKey(ecdsa)
            : leaf.GetRSAPublicKey() is { } rsa
                ? new RsaSecurityKey(rsa)
                : throw new SdJwtProcessingException(
                    ErrorCodes.IssuerKeyUnresolvable, "The end-entity certificate carries neither an EC nor an RSA public key.");

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

        // SAN uniformResourceIdentifier entries are not enumerable via the platform API; fall back to
        // the formatted extension text, which includes URI entries on all platforms.
        return sanExtensions.Any(san => san.Format(false).Contains(iss, StringComparison.OrdinalIgnoreCase));
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
