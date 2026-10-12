namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// The <c>VerificationResult.Valid</c> / <c>VerificationResult.Invalid</c> factory helpers let tests and
/// self-driving hosts synthesize results without hand-populating every required member.
/// </summary>
public sealed class VerificationResultFactoryTests
{
    private static readonly IssuerInfo Issuer = new()
    {
        Identifier = "https://issuer.example",
        Trusted = true,
        KeyResolutionMethod = "jwt-vc-issuer-metadata",
    };

    [Fact]
    public void Valid_CarriesClaimsAndIssuer_WithNoErrors()
    {
        var claims = new Dictionary<string, object> { ["age_over_18"] = true };

        var result = VerificationResult.Valid(claims, Issuer);

        Assert.True(result.IsValid);
        Assert.Same(claims, result.DisclosedClaims);
        Assert.Same(Issuer, result.Issuer);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Invalid_SingleError_DefaultsToUnknownIssuer()
    {
        var error = new VerificationError { Code = "structure_invalid", Message = "bad" };

        var result = VerificationResult.Invalid(error);

        Assert.False(result.IsValid);
        Assert.Empty(result.DisclosedClaims);
        Assert.Same(IssuerInfo.Unknown, result.Issuer);
        Assert.Equal("none", result.Issuer.KeyResolutionMethod);
        Assert.False(result.Issuer.Trusted);
        Assert.Equal(new[] { error }, result.Errors);
    }

    [Fact]
    public void Invalid_KeepsSuppliedIssuer_WhenResolved()
    {
        var errors = new[]
        {
            new VerificationError { Code = "signature_invalid", Message = "no" },
            new VerificationError { Code = "issuer_untrusted", Message = "no" },
        };

        var result = VerificationResult.Invalid(errors, Issuer);

        Assert.False(result.IsValid);
        Assert.Same(Issuer, result.Issuer);
        Assert.Equal(2, result.Errors.Count);
    }

    [Fact]
    public void Factories_RejectNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Valid(null!, Issuer));
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Valid(new Dictionary<string, object>(), null!));
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Invalid((VerificationError)null!));
        Assert.Throws<ArgumentNullException>(() => VerificationResult.Invalid((IReadOnlyList<VerificationError>)null!));
    }

    /// <summary>
    /// A message quotes what the presenter sent, so <c>Invalid</c> makes every message one line before a
    /// caller can log it. Every character that could break the line becomes U+FFFD; the code is kept.
    /// </summary>
    [Fact]
    public void Invalid_MakesEveryMessageOneLine_AndKeepsTheCode()
    {
        const string hostile = "Evil\nINFO: forged\r\u0085next\u2028and\u2029end";
        // The hostile message is NOT the first error, so a rule applied to the first message alone fails here.
        var result = VerificationResult.Invalid(
        [
            new VerificationError { Code = "first", Message = "A clean message." },
            new VerificationError { Code = "second", Message = $"Issuer '{hostile}' is not trusted." },
        ]);

        Assert.Equal(["first", "second"], result.Errors.Select(e => e.Code));
        foreach (var error in result.Errors)
        {
            Assert.DoesNotContain(error.Message, c => char.IsControl(c) || c is '\u2028' or '\u2029');
        }

        Assert.Equal("A clean message.", result.Errors[0].Message);
        Assert.Equal("Issuer 'Evil" + "\uFFFD" + "INFO: forged" + "\uFFFD" + "\uFFFD" + "next" + "\uFFFD" + "and" + "\uFFFD" + "end' is not trusted.", result.Errors[1].Message);
    }

    /// <summary>
    /// <c>Invalid</c> is where messages are made one line, so nothing else in the library may set a result's
    /// errors, apart from the session view, which replaces every message with one fixed sentence. This reads
    /// the source rather than a running path, because a new failure path that set <c>Errors</c> itself would
    /// skip the rule without any test of that path noticing.
    /// </summary>
    [Fact]
    public void NoLibrarySource_SetsAResultsErrors_ExceptTheFactory()
    {
        var src = Path.Combine(RepositoryRoot(), "src");
        // By path, not file name, so a new file that happens to share a name is not exempt. SessionView
        // replaces every message with one fixed sentence, so nothing a presenter sent survives there.
        string[] allowed =
        [
            Path.Combine("Tessio.Verifier.Core", "VerificationResult.cs"),
            Path.Combine("Tessio.Verifier.AspNetCore", "SessionView.cs"),
        ];
        // Over the whole file, so an assignment split across lines is still found: \s matches a line break.
        var setsErrors = new System.Text.RegularExpressions.Regex(@"\bErrors\s*=(?!\s*\[\s*\])");
        var offenders = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(f => !allowed.Contains(Path.GetRelativePath(src, f)))
            .SelectMany(f =>
            {
                var text = File.ReadAllText(f);
                return setsErrors.Matches(text).Select(m => $"{Path.GetRelativePath(src, f)}:{text[..m.Index].Count(c => c == '\n') + 1}");
            })
            .ToList();

        Assert.True(offenders.Count == 0,
            "These set a result's Errors directly, so their messages skip VerificationResult.Invalid's "
            + "one-line rule. Build the result with VerificationResult.Invalid instead: " + string.Join(", ", offenders));
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Tessio.Verifier.sln"))) return dir.FullName;
        }

        throw new InvalidOperationException("Tessio.Verifier.sln not found above the test assembly.");
    }
}
