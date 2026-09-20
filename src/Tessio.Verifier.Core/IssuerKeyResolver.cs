using System.Formats.Asn1;
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

    /// <summary>GeneralName CHOICE tags, RFC 5280 section 4.2.1.6.</summary>
    private const int DnsGeneralNameTag = 2;

    /// <inheritdoc cref="DnsGeneralNameTag"/>
    private const int UriGeneralNameTag = 6;

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
        // six is an ISSUER Alternative Name, OID 2.5.29.18, one digit from the OID used here and carrying
        // an unrelated URL. Matching "any name-ish extension" would pull that URL into issuer matching.
        //
        // The check is KEPT where it has something to compare, so a certificate naming one host cannot
        // vouch for an iss naming another. Authenticity still rests on the chain reaching a configured
        // trust anchor, which is the control that was doing the real work all along.
        //
        // FOUND BY OID, never by the parsed CLR type, and the difference is a security one. This branch
        // is the only place that turns "we found nothing" into "accept".
        // X509SubjectAlternativeNameExtension is a PARSED view, so a runtime that handed back a plain
        // X509Extension for this OID would make a typed list empty on a certificate that does assert
        // names, and keying acceptance on that would vouch for somebody else's certificate. The OID is
        // present or it is not, on every platform.
        var sanExtensions = certificate.Extensions
            .Where(e => string.Equals(e.Oid?.Value, SubjectAltNameOid, StringComparison.Ordinal))
            .ToList();

        if (sanExtensions.Count == 0)
        {
            return true;
        }

        var issHost = Uri.TryCreate(iss, UriKind.Absolute, out var issUri) ? issUri.Host : null;

        foreach (var name in sanExtensions.SelectMany(ReadGeneralNames))
        {
            var matched = name.Tag switch
            {
                DnsGeneralNameTag => string.Equals(name.Value, issHost ?? iss, StringComparison.OrdinalIgnoreCase),
                UriGeneralNameTag => IsSameUri(name.Value, iss),
                _ => false,
            };

            if (matched)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Reads the dNSName and uniformResourceIdentifier entries out of a SAN extension's DER.</summary>
    /// <remarks>
    /// THE DER, not the platform's rendering of it. This used to read <c>EnumerateDnsNames</c> plus a
    /// substring test over <c>Format(false)</c>, and both are platform-dependent: Windows labels and
    /// punctuates the formatted text differently from Unix, so a certificate whose SAN URI matched
    /// exactly was accepted on one operating system and refused on another. Caught by Windows CI on
    /// 2026-09-20, which the release workflow does not run. RFC 5280 section 4.2.1.6 gives GeneralName
    /// as a CHOICE with implicit context tags, so the bytes say the same thing everywhere.
    /// <para>
    /// A SAN that does not parse yields no names, so nothing matches and the caller refuses. An
    /// unreadable assertion of a name is not an absent one.
    /// </para>
    /// </remarks>
    private static List<(int Tag, string Value)> ReadGeneralNames(X509Extension extension)
    {
        var names = new List<(int, string)>();
        try
        {
            var sequence = new AsnReader(extension.RawData, AsnEncodingRules.DER).ReadSequence();
            while (sequence.HasData)
            {
                var tag = sequence.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific
                    && tag.TagValue is DnsGeneralNameTag or UriGeneralNameTag)
                {
                    names.Add((tag.TagValue, sequence.ReadCharacterString(UniversalTagNumber.IA5String, tag)));
                }
                else
                {
                    sequence.ReadEncodedValue();
                }
            }
        }
        catch (AsnContentException)
        {
            return names;
        }

        return names;
    }

    /// <summary>Whether a SAN URI entry names exactly <paramref name="iss"/>.</summary>
    /// <remarks>
    /// Compared as URIs when both parse, so a trailing slash is not a mismatch, and as exact strings
    /// otherwise. NEVER as a prefix or a substring: the earlier substring test meant a SAN of
    /// <c>https://issuer.example.attacker.test/</c> satisfied <c>iss = https://issuer.example</c>, so
    /// registering a lookalike domain was the whole attack.
    /// </remarks>
    private static bool IsSameUri(string entry, string iss) =>
        Uri.TryCreate(entry, UriKind.Absolute, out var entryUri)
        && Uri.TryCreate(iss, UriKind.Absolute, out var issAsUri)
            ? Uri.Compare(
                entryUri, issAsUri, UriComponents.AbsoluteUri, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0
            : string.Equals(entry, iss, StringComparison.OrdinalIgnoreCase);

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
