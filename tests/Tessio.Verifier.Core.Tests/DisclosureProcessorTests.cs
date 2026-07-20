using System.Text.Json.Nodes;

namespace Tessio.Verifier.Core.Tests;

/// <summary>RFC 9901 §7.1 MUST-reject rules, exercised directly against the processor.</summary>
public class DisclosureProcessorTests
{
    private static JsonObject PayloadWithSd(params string[] digests) =>
        new() { ["_sd"] = new JsonArray(digests.Select(d => (JsonNode)d).ToArray()) };

    [Fact]
    public void DuplicateDigest_InSdArray_Rejects()
    {
        var disclosure = TestCredentialBuilder.MakeDisclosure("a", 1);
        var digest = DisclosureProcessor.ComputeDigest(disclosure);

        var e = Assert.Throws<SdJwtProcessingException>(
            () => DisclosureProcessor.Process(PayloadWithSd(digest, digest), [disclosure]));
        Assert.Equal(ErrorCodes.DigestDuplicated, e.Code);
    }

    [Fact]
    public void UnreferencedDisclosure_Rejects()
    {
        var referenced = TestCredentialBuilder.MakeDisclosure("a", 1);
        var stray = TestCredentialBuilder.MakeDisclosure("b", 2);

        var e = Assert.Throws<SdJwtProcessingException>(() => DisclosureProcessor.Process(
            PayloadWithSd(DisclosureProcessor.ComputeDigest(referenced)), [referenced, stray]));
        Assert.Equal(ErrorCodes.DisclosureUnreferenced, e.Code);
    }

    [Fact]
    public void ReservedClaimName_InDisclosure_Rejects()
    {
        var disclosure = TestCredentialBuilder.MakeDisclosure("_sd", new[] { "x" });

        var e = Assert.Throws<SdJwtProcessingException>(() => DisclosureProcessor.Process(
            PayloadWithSd(DisclosureProcessor.ComputeDigest(disclosure)), [disclosure]));
        Assert.Equal(ErrorCodes.ClaimNameReserved, e.Code);
    }

    [Fact]
    public void DuplicateClaimName_DisclosureCollidesWithPlainClaim_Rejects()
    {
        var disclosure = TestCredentialBuilder.MakeDisclosure("email", "a@example.com");
        var payload = PayloadWithSd(DisclosureProcessor.ComputeDigest(disclosure));
        payload["email"] = "plain@example.com";

        var e = Assert.Throws<SdJwtProcessingException>(
            () => DisclosureProcessor.Process(payload, [disclosure]));
        Assert.Equal(ErrorCodes.ClaimNameDuplicated, e.Code);
    }

    [Fact]
    public void TopLevelRegisteredClaim_ViaDisclosure_Rejects()
    {
        var disclosure = TestCredentialBuilder.MakeDisclosure("iss", "https://evil.example");

        var e = Assert.Throws<SdJwtProcessingException>(() => DisclosureProcessor.Process(
            PayloadWithSd(DisclosureProcessor.ComputeDigest(disclosure)), [disclosure]));
        Assert.Equal(ErrorCodes.ClaimNotDisclosable, e.Code);
    }

    [Fact]
    public void UnsupportedSdAlg_Rejects()
    {
        var payload = new JsonObject { ["_sd_alg"] = "sha-512" };

        var e = Assert.Throws<SdJwtProcessingException>(() => DisclosureProcessor.Process(payload, []));
        Assert.Equal(ErrorCodes.SdAlgUnsupported, e.Code);
    }

    [Fact]
    public void ObjectDisclosure_ReferencedFromArraySlot_Rejects()
    {
        var objectDisclosure = TestCredentialBuilder.MakeDisclosure("name", "value");
        var payload = new JsonObject
        {
            ["list"] = new JsonArray(new JsonObject
            {
                [SdJwtConstants.ArrayDigestKey] = DisclosureProcessor.ComputeDigest(objectDisclosure),
            }),
        };

        var e = Assert.Throws<SdJwtProcessingException>(
            () => DisclosureProcessor.Process(payload, [objectDisclosure]));
        Assert.Equal(ErrorCodes.DisclosureInvalid, e.Code);
    }

    [Fact]
    public void RecursiveDisclosure_NestedSdInsideDisclosedValue_Resolves()
    {
        // SPEC: RFC 9901 §4.2.6 — a disclosed value may itself carry _sd digests.
        var innerDisclosure = TestCredentialBuilder.MakeDisclosure("street", "Schulstr. 12");
        var address = new Dictionary<string, object>
        {
            ["_sd"] = new[] { DisclosureProcessor.ComputeDigest(innerDisclosure) },
            ["country"] = "DE",
        };
        var outerDisclosure = TestCredentialBuilder.MakeDisclosure("address", address);

        var processed = DisclosureProcessor.Process(
            PayloadWithSd(DisclosureProcessor.ComputeDigest(outerDisclosure)),
            [outerDisclosure, innerDisclosure]);

        var processedAddress = processed["address"]!.AsObject();
        Assert.Equal("Schulstr. 12", processedAddress["street"]!.GetValue<string>());
        Assert.Equal("DE", processedAddress["country"]!.GetValue<string>());
        Assert.False(processedAddress.ContainsKey("_sd"));
    }

    [Fact]
    public void DecoyDigests_AreIgnored_NotRejected()
    {
        var disclosure = TestCredentialBuilder.MakeDisclosure("a", 1);
        var decoy = DisclosureProcessor.ComputeDigest(TestCredentialBuilder.MakeDisclosure("never", 0));

        var processed = DisclosureProcessor.Process(
            PayloadWithSd(DisclosureProcessor.ComputeDigest(disclosure), decoy), [disclosure]);

        Assert.Equal(1, processed["a"]!.GetValue<int>());
    }

    [Fact]
    public void MalformedDisclosure_NotAJsonArray_Rejects()
    {
        var bogus = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode("{\"not\":\"an array\"}");
        var payload = PayloadWithSd(DisclosureProcessor.ComputeDigest(bogus));

        var e = Assert.Throws<SdJwtProcessingException>(() => DisclosureProcessor.Process(payload, [bogus]));
        Assert.Equal(ErrorCodes.DisclosureInvalid, e.Code);
    }
}
