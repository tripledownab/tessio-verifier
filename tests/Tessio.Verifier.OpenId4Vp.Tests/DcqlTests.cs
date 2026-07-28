using System.Text.Json;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The public <see cref="Dcql"/> builders produce the single-credential DCQL query shapes the verifier
/// requests, so hosts assembling their own <see cref="PresentationRequestOptions"/> do not hand-write JSON.
/// </summary>
public sealed class DcqlTests
{
    private static JsonElement TheOnlyCredential(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var credentials = doc.RootElement.GetProperty("credentials");
        Assert.Equal(1, credentials.GetArrayLength());
        // Clone so the value outlives the disposed document.
        return credentials[0].Clone();
    }

    [Fact]
    public void SdJwtVc_BuildsSingleCredentialWithVctAndClaimPaths()
    {
        var credential = TheOnlyCredential(Dcql.SdJwtVc("https://issuer.example/vct/pid", "given_name", "age_over_18"));

        Assert.Equal(Dcql.DefaultCredentialId, credential.GetProperty("id").GetString());
        Assert.Equal("dc+sd-jwt", credential.GetProperty("format").GetString());
        Assert.Equal(
            "https://issuer.example/vct/pid",
            credential.GetProperty("meta").GetProperty("vct_values")[0].GetString());

        var claims = credential.GetProperty("claims");
        Assert.Equal(2, claims.GetArrayLength());
        Assert.Equal("given_name", claims[0].GetProperty("path")[0].GetString());
        Assert.Equal("age_over_18", claims[1].GetProperty("path")[0].GetString());
    }

    [Fact]
    public void AgeOver_RequestsTheAgeOverClaim()
    {
        var credential = TheOnlyCredential(Dcql.AgeOver(21, "https://issuer.example/vct/pid"));

        var claims = credential.GetProperty("claims");
        Assert.Equal(1, claims.GetArrayLength());
        Assert.Equal("age_over_21", claims[0].GetProperty("path")[0].GetString());
    }

    [Fact]
    public void Mdoc_BuildsDoctypeAndTwoElementPaths()
    {
        var credential = TheOnlyCredential(
            Dcql.Mdoc("org.iso.18013.5.1.mDL", "org.iso.18013.5.1", "age_over_18"));

        Assert.Equal("mso_mdoc", credential.GetProperty("format").GetString());
        Assert.Equal("org.iso.18013.5.1.mDL", credential.GetProperty("meta").GetProperty("doctype_value").GetString());

        var path = credential.GetProperty("claims")[0].GetProperty("path");
        Assert.Equal("org.iso.18013.5.1", path[0].GetString());
        Assert.Equal("age_over_18", path[1].GetString());
    }

    [Fact]
    public void SdJwtVc_KeepsThePlusInTheFormatLiteral()
    {
        // Relaxed escaping must keep "dc+sd-jwt" literal rather than emitting +.
        Assert.Contains("\"dc+sd-jwt\"", Dcql.SdJwtVc("https://issuer.example/vct", "sub"), StringComparison.Ordinal);
    }

    [Fact]
    public void Builders_RejectEmptyRequiredArguments()
    {
        Assert.Throws<ArgumentException>(() => Dcql.SdJwtVc("", "sub"));
        Assert.Throws<ArgumentException>(() => Dcql.SdJwtVc("vct", ""));
        Assert.Throws<ArgumentOutOfRangeException>(() => Dcql.AgeOver(0, "vct"));
        Assert.Throws<ArgumentException>(() => Dcql.Mdoc("doc", "", "el"));
    }
}
