using System.Text.Json.Nodes;

namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Known-answer vectors taken verbatim from the SD-JWT specification (RFC 9901 §4.2.3 and §4.2.4.2).
/// If these fail, the digest computation is wrong and nothing else can be trusted.
/// </summary>
public class SpecVectorTests
{
    // RFC 9901 §4.2.3 — disclosure of ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"].
    private const string FamilyNameDisclosure = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0";
    private const string FamilyNameDigest = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0";

    // RFC 9901 §4.2.4.2 — array-element disclosure of ["lklxF5jMYlGTPUovMNIvCA", "FR"].
    private const string NationalityFrDisclosure = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0";
    private const string NationalityFrDigest = "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs";

    [Fact]
    public void ComputeDigest_MatchesSpecKnownAnswer_ObjectProperty()
    {
        Assert.Equal(FamilyNameDigest, DisclosureProcessor.ComputeDigest(FamilyNameDisclosure));
    }

    [Fact]
    public void ComputeDigest_MatchesSpecKnownAnswer_ArrayElement()
    {
        Assert.Equal(NationalityFrDigest, DisclosureProcessor.ComputeDigest(NationalityFrDisclosure));
    }

    [Fact]
    public void Process_SpecFamilyNameDisclosure_RoundTrips()
    {
        var payload = new JsonObject
        {
            ["_sd"] = new JsonArray(FamilyNameDigest),
            ["_sd_alg"] = "sha-256",
        };

        var processed = DisclosureProcessor.Process(payload, [FamilyNameDisclosure]);

        Assert.Equal("Möbius", processed["family_name"]!.GetValue<string>());
        Assert.False(processed.ContainsKey("_sd"));
        Assert.False(processed.ContainsKey("_sd_alg"));
    }

    [Fact]
    public void Process_SpecNationalitiesArray_DisclosesElementAndRemovesUndisclosed()
    {
        // RFC 9901 §4.2.4.2 example: ["DE", {"...": <FR digest>}, {"...": <unknown digest>}].
        var payload = new JsonObject
        {
            ["nationalities"] = new JsonArray(
                "DE",
                new JsonObject { [SdJwtConstants.ArrayDigestKey] = NationalityFrDigest },
                new JsonObject { [SdJwtConstants.ArrayDigestKey] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
        };

        var processed = DisclosureProcessor.Process(payload, [NationalityFrDisclosure]);

        var nationalities = processed["nationalities"]!.AsArray();
        Assert.Equal(2, nationalities.Count);
        Assert.Equal("DE", nationalities[0]!.GetValue<string>());
        Assert.Equal("FR", nationalities[1]!.GetValue<string>());
    }
}
