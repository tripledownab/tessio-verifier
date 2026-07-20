using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// The MOCK-mode wallet: issues real, signed SD-JWT VC presentations with an ephemeral ES256 issuer
/// key and a self-signed certificate, so the full verification pipeline runs offline. Key resolution
/// uses <c>x5c</c> (no network); trust comes from registering <see cref="Issuer"/> on the trust list.
/// </summary>
internal sealed class MockCredentialIssuer : IDisposable
{
    /// <summary>The mock issuer identifier; its host matches the certificate's SAN.</summary>
    public const string Issuer = "https://mock-issuer.tessio.dev";

    private readonly ECDsa _issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _holderKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 _certificate;

    public MockCredentialIssuer()
    {
        var request = new CertificateRequest("CN=Tessio Mock Issuer", _issuerKey, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(new Uri(Issuer).Host);
        request.CertificateExtensions.Add(san.Build());
        _certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>
    /// Issues a presentation for the requested claims, bound to the session's nonce and the
    /// verifier's audience: <c>&lt;issuer-jwt&gt;~&lt;disclosures…&gt;~&lt;kb-jwt&gt;</c>.
    /// </summary>
    public string IssuePresentation(IEnumerable<string> claimNames, string vct, string nonce, string audience)
    {
        var disclosures = claimNames
            .Select(name => MakeDisclosure(name, SampleClaimValues.For(name)))
            .ToList();

        var holderPublic = _holderKey.ExportParameters(false);
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["vct"] = vct,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds(),
            ["_sd_alg"] = "sha-256",
            ["_sd"] = disclosures.Select(ComputeDigest).ToList(),
            ["cnf"] = new Dictionary<string, object>
            {
                ["jwk"] = new Dictionary<string, object>
                {
                    ["kty"] = "EC",
                    ["crv"] = "P-256",
                    ["x"] = Base64UrlEncoder.Encode(holderPublic.Q.X!),
                    ["y"] = Base64UrlEncoder.Encode(holderPublic.Q.Y!),
                },
            },
        };

        var issuerJwt = SignJwt(
            JsonSerializer.Serialize(payload),
            new ECDsaSecurityKey(_issuerKey),
            typ: "dc+sd-jwt",
            x5c: [Convert.ToBase64String(_certificate.RawData)]);

        var withoutKb = issuerJwt + "~" + string.Concat(disclosures.Select(d => d + "~"));

        // SPEC: RFC 9901 §4.3 — KB-JWT binds the presentation to this verifier's nonce and audience.
        var kbPayload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["aud"] = audience,
            ["nonce"] = nonce,
            ["sd_hash"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(withoutKb))),
        });

        return withoutKb + SignJwt(kbPayload, new ECDsaSecurityKey(_holderKey), typ: "kb+jwt", x5c: null);
    }

    private static string MakeDisclosure(string name, object? value) =>
        Base64UrlEncoder.Encode(JsonSerializer.Serialize(new[]
        {
            Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)), // 128-bit salt (RFC 9901 §9.3)
            name,
            value,
        }));

    private static string ComputeDigest(string disclosure) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));

    private static string SignJwt(string payload, SecurityKey key, string typ, List<string>? x5c)
    {
        var headers = new Dictionary<string, object> { ["typ"] = typ };
        if (x5c is not null)
        {
            headers["x5c"] = x5c;
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(
            payload,
            new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
            headers);
    }

    public void Dispose()
    {
        _issuerKey.Dispose();
        _holderKey.Dispose();
        _certificate.Dispose();
    }
}
