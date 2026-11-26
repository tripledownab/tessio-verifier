using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tessio.Verifier.Trust.Tests;

/// <summary>
/// What belongs here: that a trust reason is one line however the presented certificates are named.
/// A reason quotes the presented chain's names, which whoever issued those certificates chose.
/// </summary>
public sealed class MessageTextTests
{
    private const string Issuer = "https://issuer.example";

    // Line feed, carriage return, NEL (a C1 control), and the two Unicode line separators.
    private const string Hostile = "Evil\nINFO: forged\r\u0085next\u2028and\u2029end";

    [Fact]
    public async Task AReasonQuotingHostileCertificateNames_IsOneLine()
    {
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var anchorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var caRequest = new CertificateRequest(Named("CA " + Hostile), caKey, HashAlgorithmName.SHA256);
        caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var leaf = new CertificateRequest(Named("Leaf " + Hostile), leafKey, HashAlgorithmName.SHA256)
            .Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(20), Guid.NewGuid().ToByteArray());
        using var anchor = new CertificateRequest("CN=An Unrelated Anchor", anchorKey, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        // The leaf alone: the reason then quotes the leaf's issuer name AND the top of the chain, the leaf.
        var status = await new StaticTrustListResolver([Issuer], trustAnchors: [anchor]).ResolveAsync(Issuer, [leaf.RawData]);

        Assert.False(status.Trusted);
        Assert.NotNull(status.Reason);
        Assert.DoesNotContain(status.Reason, c => char.IsControl(c) || c is '\u2028' or '\u2029');
        // The names are still quoted, with each line-breaking character shown as U+FFFD.
        Assert.Contains("Evil" + "\uFFFD" + "INFO: forged", status.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void OneLine_ReturnsACleanMessageUnchanged()
    {
        const string clean = "Issuer 'https://issuer.example' is not on the configured trust list.";
        Assert.Same(clean, MessageText.OneLine(clean));
    }

    [Fact]
    public void OneLine_KeepsAMessageOfTheLimitWhole()
    {
        var message = new string('m', MessageText.MaxLength);
        Assert.Same(message, MessageText.OneLine(message));
    }

    [Fact]
    public void OneLine_CutsALongerMessageToTheLimit()
    {
        // A presenter chooses how long a quoted value is; 100 000 characters stands for any of them.
        var cut = MessageText.OneLine("Element '" + new string('q', 100_000) + "' is refused.");

        Assert.Equal(MessageText.MaxLength, cut.Length);
        Assert.StartsWith("Element 'qqq", cut, StringComparison.Ordinal);
        Assert.EndsWith("…", cut, StringComparison.Ordinal);
    }

    [Fact]
    public void OneLine_NeverCutsASurrogatePairInHalf()
    {
        // An emoji, two UTF-16 units, placed so the cut would fall between them.
        var message = new string('m', MessageText.MaxLength - 2) + "😀" + new string('m', 10);

        var cut = MessageText.OneLine(message);

        Assert.False(char.IsHighSurrogate(cut[^2]));
        Assert.EndsWith("…", cut, StringComparison.Ordinal);
    }

    [Fact]
    public void OneLine_CutsBeforeItReplaces_SoALongHostileMessageIsStillOneLine()
    {
        var cut = MessageText.OneLine(new string('x', 2000) + "\nforged line");

        Assert.DoesNotContain('\n', cut);
        Assert.Equal(MessageText.MaxLength, cut.Length);
    }

    private static X500DistinguishedName Named(string commonName)
    {
        var name = new X500DistinguishedNameBuilder();
        name.AddCommonName(commonName);
        return name.Build();
    }
}
