// What belongs here: Dcql.WithTrustedAuthorities, the aki Trusted Authorities Query added to a DCQL query.
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Tessio.Verifier.OpenId4Vp.Tests;

public sealed class DcqlTrustedAuthoritiesTests
{
    // Chosen, not derived from the key, so an implementation that hashes the key instead of reading the
    // extension fails. Base64 of these bytes contains '+' and '/', which base64url does not.
    private static readonly byte[] SubjectKeyIdentifier = [.. Enumerable.Range(0, 20).Select(i => (byte)(i % 2 == 0 ? 0xFB : 0xFF))];
    private static readonly byte[] OtherSubjectKeyIdentifier = [.. Enumerable.Range(0, 20).Select(i => (byte)(0xBF - i))];

    [Fact]
    public void The_value_is_what_a_credential_issued_under_the_certificate_carries_as_its_authority_key_identifier()
    {
        // SPEC: OpenID4VP 1.0 section 6.1.1.1: the value's raw bytes "MUST match with the
        // AuthorityKeyIdentifier element" of a certificate in the credential's chain.
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority(caKey);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=Document Signer", leafKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
            ca, true, false));
        using var leaf = leafRequest.Create(ca, ca.NotBefore, ca.NotAfter, [1, 2, 3]);
        var leafAki = leaf.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single().KeyIdentifier!.Value.ToArray();

        var query = Dcql.WithTrustedAuthorities(Dcql.Mdoc("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18"), [ca]);

        var authority = Assert.Single(Credentials(query)[0].GetProperty("trusted_authorities").EnumerateArray());
        Assert.Equal("aki", authority.GetProperty("type").GetString());
        var value = Assert.Single(authority.GetProperty("values").EnumerateArray()).GetString()!;
        // Spelled out rather than decoded, because a lenient decoder also accepts standard base64.
        Assert.Equal(Convert.ToBase64String(leafAki).TrimEnd('=').Replace('+', '-').Replace('/', '_'), value);
    }

    [Fact]
    public void A_real_iaca_gives_the_value_its_document_signer_carries()
    {
        using var iaca = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(AppContext.BaseDirectory, "Fixtures", "mdoc-iaca.der"));
        using var documentSigner = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(AppContext.BaseDirectory, "Fixtures", "mdoc-document-signer.der"));

        Assert.Equal(
            UrlSafe(documentSigner.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single().KeyIdentifier!.Value.ToArray()),
            Assert.Single(Values(Dcql.WithTrustedAuthorities(Dcql.Mdoc("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18"), [iaca]))));
    }

    [Fact]
    public void An_intermediate_ca_gives_its_own_subject_key_identifier_not_its_issuers()
    {
        // An intermediate carries both: its SKI, which the certificates it issues name, and an AKI naming
        // the root above it. Only the first matches a credential signed under the intermediate.
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = CertificateAuthority(rootKey, OtherSubjectKeyIdentifier);
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test intermediate", intermediateKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(SubjectKeyIdentifier, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(root, true, false));
        using var intermediate = request.Create(root, root.NotBefore, root.NotAfter, [4, 5, 6]);

        Assert.Equal(UrlSafe(SubjectKeyIdentifier), Assert.Single(Values(Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [intermediate]))));
    }

    [Fact]
    public void A_pinned_signing_certificate_gives_its_authority_key_identifier()
    {
        // Not a CA, so nothing names its SKI as an AKI. What a credential signed with it carries is the
        // certificate itself, whose AKI is the value that matches.
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority(caKey, OtherSubjectKeyIdentifier);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Pinned signer", leafKey, HashAlgorithmName.SHA256);
        // CA:FALSE and critical, the shape of a real AV list's signing certificate: present BasicConstraints
        // is not CA status, and neither is criticality.
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(SubjectKeyIdentifier, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
        using var leaf = request.Create(ca, ca.NotBefore, ca.NotAfter, [7, 8, 9]);

        Assert.Equal(UrlSafe(OtherSubjectKeyIdentifier), Assert.Single(Values(Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [leaf]))));
    }

    [Fact]
    public void Every_credential_in_the_query_gets_it_and_the_rest_of_the_query_is_kept()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority(caKey);
        const string handWritten = """
            {"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}},
            {"id":"mdl","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}],
            "credential_sets":[{"options":[["pid"],["mdl"]]}]}
            """;

        var query = Dcql.WithTrustedAuthorities(handWritten, [ca]);

        var credentials = Credentials(query);
        Assert.Equal(2, credentials.Length);
        Assert.All(credentials, credential => Assert.True(credential.TryGetProperty("trusted_authorities", out _)));
        Assert.Equal("urn:eudi:pid:1", credentials[0].GetProperty("meta").GetProperty("vct_values")[0].GetString());
        using var document = JsonDocument.Parse(query);
        Assert.True(document.RootElement.TryGetProperty("credential_sets", out _));
    }

    [Fact]
    public void Two_certificates_with_one_key_identifier_are_listed_once_and_two_different_ones_twice()
    {
        using var firstKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var secondKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var first = CertificateAuthority(firstKey);
        using var firstAgain = CertificateAuthority(secondKey);
        using var second = CertificateAuthority(secondKey, OtherSubjectKeyIdentifier);

        Assert.Single(Values(Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [first, firstAgain])));
        Assert.Equal(2, Values(Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [first, second])).Length);

        // Base64url is case sensitive: 0x00 and 0x68 as the first byte encode as "A" and "a".
        using var lower = CertificateAuthority(firstKey, [0x00, .. SubjectKeyIdentifier[1..]]);
        using var upper = CertificateAuthority(secondKey, [0x68, .. SubjectKeyIdentifier[1..]]);
        var values = Values(Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [lower, upper]));
        Assert.Equal(2, values.Length);
        Assert.Equal(values[0], values[1], ignoreCase: true);
    }

    [Fact]
    public void A_certificate_list_that_cannot_name_an_authority_is_refused()
    {
        var query = Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18");
        Assert.Equal("trustedIssuerCertificates", Assert.Throws<ArgumentNullException>(() => Dcql.WithTrustedAuthorities(query, null!)).ParamName);
        Assert.Equal("trustedIssuerCertificates", Assert.Throws<ArgumentException>(() => Dcql.WithTrustedAuthorities(query, [])).ParamName);
        Assert.Equal("trustedIssuerCertificates", Assert.Throws<ArgumentException>(
            () => Dcql.WithTrustedAuthorities(query, [null!])).ParamName);
    }

    // Each lacks the identifier its role contributes, and has the other one, so falling back to it fails.
    // DER is written out where .NET's constructors refuse the value: an empty key identifier.
    [Theory]
    [InlineData(false, "subject", "")]                          // an end entity with an SKI and no AKI
    [InlineData(true, "", "authority")]                         // a CA with an AKI and no SKI
    [InlineData(true, "empty", "authority")]                    // a CA whose SKI is empty
    [InlineData(false, "subject", "empty")]                     // an end entity whose AKI is empty
    public void A_certificate_without_the_identifier_its_role_contributes_is_refused(bool isCa, string subject, string authority)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Refused", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        switch (subject)
        {
            case "subject": request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(SubjectKeyIdentifier, false)); break;
            case "empty": request.CertificateExtensions.Add(new X509Extension("2.5.29.14", [0x04, 0x00], false)); break;
        }

        switch (authority)
        {
            case "authority": request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(OtherSubjectKeyIdentifier)); break;
            case "empty": request.CertificateExtensions.Add(new X509Extension("2.5.29.35", [0x30, 0x02, 0x80, 0x00], false)); break;
        }

        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.Equal("trustedIssuerCertificates", Assert.Throws<ArgumentException>(
            () => Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [certificate])).ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("""{"credentials":[{"id":"c","format":"mso_mdoc","trusted_authorities":null}]}""")]
    [InlineData("""{"credentials":[]}""")]
    [InlineData("""{"credentials":["not an object"]}""")]
    [InlineData("""{"credential_sets":[]}""")]
    [InlineData("""{"credentials":[{"id":"c","format":"mso_mdoc","trusted_authorities":[{"type":"aki","values":["a"]}]}]}""")]
    public void A_query_it_cannot_add_to_unambiguously_is_refused(string query)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var ca = CertificateAuthority(key);

        Assert.Equal("dcqlQueryJson", Assert.Throws<ArgumentException>(() => Dcql.WithTrustedAuthorities(query, [ca])).ParamName);
    }

    [Fact]
    public void A_certificate_repeating_an_extension_is_refused()
    {
        // RFC 5280 section 4.2 forbids two instances of one extension, and .NET will not build such a
        // certificate, so one is built with a placeholder OID that the DER is then patched to repeat.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Repeats its SKI", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(SubjectKeyIdentifier, false));
        request.CertificateExtensions.Add(new X509Extension("2.5.29.99", new X509SubjectKeyIdentifierExtension(OtherSubjectKeyIdentifier, false).RawData, false));
        using var built = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        var der = built.RawData;
        byte[] placeholder = [0x06, 0x03, 0x55, 0x1D, 0x63];
        var at = der.AsSpan().IndexOf(placeholder);
        Assert.True(at > 0);
        der[at + 4] = 0x0E;
        using var repeating = X509CertificateLoader.LoadCertificate(der);
        Assert.Equal(2, repeating.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Count());

        Assert.Equal("trustedIssuerCertificates", Assert.Throws<ArgumentException>(
            () => Dcql.WithTrustedAuthorities(Dcql.SdJwtVc("urn:eudi:pid:1", "age_over_18"), [repeating])).ParamName);
    }

    private static X509Certificate2 CertificateAuthority(ECDsa key, byte[]? subjectKeyIdentifier = null)
    {
        var request = new CertificateRequest("CN=Test IACA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(subjectKeyIdentifier ?? SubjectKeyIdentifier, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    // Spelled out rather than through the library's encoder, so the test does not share its mistakes.
    private static string UrlSafe(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static JsonElement[] Credentials(string query)
    {
        using var document = JsonDocument.Parse(query);
        return [.. document.RootElement.GetProperty("credentials").EnumerateArray().Select(element => element.Clone())];
    }

    private static string[] Values(string query) =>
        [.. Credentials(query)[0].GetProperty("trusted_authorities")[0].GetProperty("values").EnumerateArray().Select(value => value.GetString()!)];
}
