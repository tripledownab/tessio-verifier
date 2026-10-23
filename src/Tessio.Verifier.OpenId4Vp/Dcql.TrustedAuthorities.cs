// What belongs here: the DCQL Trusted Authorities Query, added to a query the other builders made or a
// caller wrote by hand.
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.OpenId4Vp;

public static partial class Dcql
{
    // SPEC: OpenID4VP 1.0 section 6.1.1.1 names this type for Authority Key Identifiers.
    private const string AuthorityKeyIdentifierType = "aki";

    /// <summary>
    /// <paramref name="dcqlQueryJson"/> with every credential in it asking for credentials issued under
    /// <paramref name="trustedIssuerCertificates"/>, as an <c>aki</c> Trusted Authorities Query.
    /// </summary>
    /// <param name="dcqlQueryJson">A DCQL query, from one of the other builders or written by hand.</param>
    /// <param name="trustedIssuerCertificates">
    /// The certificates your trust list names for the trusted issuers: CA certificates such as an IACA,
    /// signing certificates such as a Document Signer, or both. A certificate whose BasicConstraints marks
    /// it a CA contributes its Subject Key Identifier, which RFC 5280 section 4.2.1.2 makes, "in conforming
    /// CA certificates", the Authority Key Identifier of every certificate it issues. Any other certificate
    /// contributes its own Authority Key Identifier, the value it carries in the credential's chain.
    /// </param>
    /// <remarks>
    /// <para>
    /// SPEC: HAIP 1.0 section 5: "The Authority Key Identifier (aki)-based Trusted Authority Query
    /// (trusted_authorities) for DCQL, as defined in section 6.1.1.1 of [OIDF.OID4VP], MUST be
    /// supported." It says how the values are built: "by collecting the relevant X.509 certificates for
    /// the trusted Issuers and including the encoded Key Identifiers from the certificates in the aki
    /// array". OpenID4VP 1.0 section 6.1.1.1 says the value is base64url, and that its raw bytes "MUST
    /// match with the AuthorityKeyIdentifier element" of a certificate in the credential's chain.
    /// </para>
    /// <para>
    /// The filter can be wider than the trust list. A signing certificate's value names the CA that issued
    /// it, so the wallet may offer any credential signed under that CA; a root names only what the root
    /// itself issued, which a credential carrying part of its chain (section 6.1.1.1) may not include.
    /// Leave out issuers trusted through metadata rather than a certificate chain, and any certificate
    /// this refuses, and ask for their credentials in a query without trusted authorities. Build the
    /// query from the same issuers as the trust list, so the two do not drift apart.
    /// </para>
    /// <para>
    /// A filter for the wallet, not a check. Section 6.1 says the wallet SHOULD return only credentials
    /// that match, and that verifiers must still verify the issuer's trust themselves: a response is
    /// verified against the trust list as before, whatever this query asked for.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentException">
    /// The query has no credentials, a credential is not an object or already names trusted
    /// authorities, no certificate is given, or a certificate is null, lacks the key identifier it would
    /// contribute, carries an empty one, or repeats an extension.
    /// </exception>
    /// <exception cref="System.Text.Json.JsonException">The query is not JSON.</exception>
    public static string WithTrustedAuthorities(
        string dcqlQueryJson, IReadOnlyList<X509Certificate2> trustedIssuerCertificates)
    {
        ArgumentException.ThrowIfNullOrEmpty(dcqlQueryJson);
        ArgumentNullException.ThrowIfNull(trustedIssuerCertificates);

        // SPEC: OpenID4VP 1.0 section 6.1.1: values is "a non-empty array".
        if (trustedIssuerCertificates.Count == 0)
        {
            throw new ArgumentException(
                "A Trusted Authorities Query needs at least one certificate.", nameof(trustedIssuerCertificates));
        }

        var values = new JsonArray();
        foreach (var certificate in trustedIssuerCertificates)
        {
            var keyIdentifier = KeyIdentifier(certificate) ?? throw new ArgumentException(
                "A trusted issuer certificate is missing, repeats an extension, or lacks the non-empty key identifier it would contribute: a Subject Key Identifier for a CA certificate, an Authority Key Identifier for any other.",
                nameof(trustedIssuerCertificates));

            // Two certificates with one key identifier name one authority, so it is listed once.
            if (!values.Any(value => value!.GetValue<string>() == keyIdentifier))
            {
                values.Add(keyIdentifier);
            }
        }

        if (JsonNode.Parse(dcqlQueryJson) is not JsonObject query
            || query["credentials"] is not JsonArray { Count: > 0 } credentials)
        {
            throw new ArgumentException("A DCQL query needs a non-empty credentials array.", nameof(dcqlQueryJson));
        }

        foreach (var node in credentials)
        {
            if (node is not JsonObject credential)
            {
                throw new ArgumentException("Every DCQL credential query must be an object.", nameof(dcqlQueryJson));
            }

            // Refused rather than merged. Section 6.1.1 matches a credential on any value of any entry, so
            // adding ours to one already there would widen what the wallet may offer, not narrow it.
            if (credential.ContainsKey("trusted_authorities"))
            {
                throw new ArgumentException(
                    "A credential in this query already names trusted authorities.", nameof(dcqlQueryJson));
            }

            credential["trusted_authorities"] = new JsonArray(new JsonObject
            {
                ["type"] = AuthorityKeyIdentifierType,
                ["values"] = values.DeepClone(),
            });
        }

        return query.ToJsonString(JsonDefaults.Relaxed);
    }

    /// <summary>
    /// The value a credential chaining to <paramref name="certificate"/> carries as an Authority Key
    /// Identifier, base64url, or null when the certificate lacks it, carries an empty one, or is malformed.
    /// </summary>
    /// <remarks>
    /// CA status is read from BasicConstraints alone, which RFC 5280 section 4.2.1.9 has conforming CAs
    /// include "in all CA certificates": a CA certificate without it is taken for an end entity.
    /// </remarks>
    private static string? KeyIdentifier(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return null;
        }

        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var subjectKeyIdentifiers = certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().ToArray();
        var authorityKeyIdentifiers = certificate.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().ToArray();

        // RFC 5280 section 4.2: "A certificate MUST NOT include more than one instance of a particular
        // extension", and which instance a wallet would read is anyone's guess.
        if (basicConstraints.Length > 1 || subjectKeyIdentifiers.Length > 1 || authorityKeyIdentifiers.Length > 1)
        {
            return null;
        }

        var bytes = basicConstraints is [{ CertificateAuthority: true }]
            ? subjectKeyIdentifiers.FirstOrDefault()?.SubjectKeyIdentifierBytes
            : authorityKeyIdentifiers.FirstOrDefault()?.KeyIdentifier;

        return bytes is { Length: > 0 } identifier ? Base64UrlEncoder.Encode(identifier.ToArray()) : null;
    }
}
