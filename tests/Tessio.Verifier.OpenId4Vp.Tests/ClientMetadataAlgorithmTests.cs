using System.Text.Json.Nodes;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The signature algorithms a request advertises for mdoc. The values are written out here on purpose, so a change
/// to what wallets are told is a change to this file too.
/// </summary>
public sealed class ClientMetadataAlgorithmTests
{
    [Theory]
    [InlineData("issuerauth_alg_values")]
    [InlineData("deviceauth_alg_values")]
    public void AnMdocRequest_AdvertisesEs256AndEsp256(string member)
    {
        // SPEC: OpenID4VP 1.0 Appendix B.2.2. A header of -9 matches only -9, and -9 matches a -7 header on P-256
        // too, so a list of -7 alone turns away a credential signed under -9.
        var metadata = JsonNode.Parse(ClientMetadata.Build("mso_mdoc"))!;

        var values = metadata["vp_formats_supported"]!["mso_mdoc"]![member]!.AsArray().Select(v => (int)v!).ToArray();

        Assert.Equal([-7, -9], values);
    }

    private static readonly JsonObject EncryptionJwk = new()
    {
        ["kty"] = "EC",
        ["crv"] = "P-256",
        ["x"] = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        ["y"] = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        ["use"] = "enc",
        ["alg"] = "ECDH-ES",
        ["kid"] = "1",
    };

    private static int[] Values(string metadata, string member) =>
        JsonNode.Parse(metadata)!["vp_formats_supported"]!["mso_mdoc"]![member]!.AsArray().Select(v => (int)v!).ToArray();

    [Fact]
    public void AnEncryptedMdocRequest_ThatAsks_AdvertisesTheDeviceMac_ForDeviceAuthOnly()
    {
        // SPEC: OpenID4VP 1.0 Appendix B.2.2, Table 2: -65537 is HMAC 256/256 using ECDH with P-256. It names a device
        // authentication method, so it never joins issuerauth_alg_values.
        var single = ClientMetadata.Build("mso_mdoc", EncryptionJwk, additionalMembers: null, advertiseDeviceMac: true);
        var several = ClientMetadata.BuildForFormats(["mso_mdoc", "dc+sd-jwt"], EncryptionJwk, advertiseDeviceMac: true);

        foreach (var metadata in new[] { single, several })
        {
            Assert.Equal([-7, -9, -65537], Values(metadata, "deviceauth_alg_values"));
            Assert.Equal([-7, -9], Values(metadata, "issuerauth_alg_values"));
        }
    }

    [Fact]
    public void AnMdocRequest_DoesNotAdvertiseTheDeviceMac_UnlessAsked_OrWithoutAKeyToAgreeIt()
    {
        // Without a published key there is nothing a wallet could key a MAC to that this verifier holds.
        Assert.Equal([-7, -9], Values(ClientMetadata.Build("mso_mdoc", EncryptionJwk), "deviceauth_alg_values"));
        Assert.Equal([-7, -9], Values(
            ClientMetadata.Build("mso_mdoc", null, additionalMembers: null, advertiseDeviceMac: true), "deviceauth_alg_values"));
        Assert.Equal([-7, -9], Values(
            ClientMetadata.BuildForFormats(["mso_mdoc"], null, advertiseDeviceMac: true), "deviceauth_alg_values"));
    }

    [Fact]
    public void AnMdocRequest_AdvertisesTheListTheVerifiersOwn()
    {
        var metadata = JsonNode.Parse(ClientMetadata.Build("mso_mdoc"))!;

        var values = metadata["vp_formats_supported"]!["mso_mdoc"]!["issuerauth_alg_values"]!.AsArray().Select(v => (int)v!);

        Assert.Equal(CoseAlgorithms.Advertised, values);
    }
}
