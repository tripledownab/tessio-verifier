using System.Text.Json.Nodes;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// Members a particular wallet asks for beside the standard <c>client_metadata</c>, such as its own relying party
/// metadata. Added, never allowed to replace what the builder writes.
/// </summary>
public sealed class ClientMetadataAdditionalMembersTests
{
    private static readonly JsonObject Jwk = new() { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = "eA", ["y"] = "eQ", ["kid"] = "1" };

    [Fact]
    public void AnAdditionalMember_IsWrittenBesideTheStandardOnes()
    {
        var json = ClientMetadata.Build("mso_mdoc", Jwk, new Dictionary<string, JsonNode?> { ["wallet_rp_metadata"] = "AQID" });
        var metadata = JsonNode.Parse(json)!.AsObject();

        Assert.Equal("AQID", (string?)metadata["wallet_rp_metadata"]);
        Assert.NotNull(metadata["vp_formats_supported"]);
        Assert.NotNull(metadata["jwks"]);
    }

    [Theory]
    [InlineData("vp_formats_supported")]
    [InlineData("jwks")]
    [InlineData("encrypted_response_enc_values_supported")]
    public void AMemberTheBuilderWrites_CannotBeReplaced(string name)
    {
        Assert.Throws<ArgumentException>(() =>
            ClientMetadata.Build("mso_mdoc", Jwk, new Dictionary<string, JsonNode?> { [name] = "x" }));
    }

    [Fact]
    public void AStandardMemberThisCallDoesNotWrite_StillCannotBeAdded()
    {
        // Without a key the builder writes no jwks, but a caller supplying one here would still be advertising a
        // key outside the one place this library builds it.
        Assert.Throws<ArgumentException>(() =>
            ClientMetadata.Build("mso_mdoc", responseEncryptionJwk: null, new Dictionary<string, JsonNode?> { ["jwks"] = new JsonObject() }));
    }

    [Fact]
    public void TheCallersNode_IsCopied_NotAttached()
    {
        var node = new JsonObject { ["a"] = 1 };
        var members = new Dictionary<string, JsonNode?> { ["extra"] = node };

        ClientMetadata.Build("mso_mdoc", Jwk, members);

        // A JsonNode belongs to one parent; attaching the caller's own would make a second Build throw.
        Assert.Null(node.Parent);
        ClientMetadata.Build("mso_mdoc", Jwk, members);
    }
}
