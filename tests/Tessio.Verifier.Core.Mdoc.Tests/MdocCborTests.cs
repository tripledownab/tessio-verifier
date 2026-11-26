using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// What belongs here: <see cref="MdocCbor"/>'s rule that a map may not give a key twice, read by what the key
/// decodes to. The guard that keeps the library's readers going through it is here too.
/// </summary>
public sealed class MdocCborTests
{
    // Repeated keys whose second copy is encoded differently from the first. Diagnostic notation, RFC 8949 section 8.
    private const string IndefiniteText = "A26161017F6161FF02"; // {"a": 1, (_ "a"): 2}
    private const string LongerInteger = "A20401180402";        // {4: 1, 4_0: 2}
    private const string LongerNegative = "A2200139000002";     // {-1: 1, -1_1: 2}

    [Theory]
    [InlineData("A2616101616102", "'a'")] // {"a": 1, "a": 2}
    [InlineData("A204010402", "4")]       // {4: 1, 4: 2}
    [InlineData(IndefiniteText, "'a'")]
    [InlineData(LongerInteger, "4")]
    [InlineData(LongerNegative, "-1")]
    public void A_map_giving_a_key_twice_is_refused(string hex, string key)
    {
        var e = Assert.Throws<CborContentException>(() => MdocCbor.Reader(Convert.FromHexString(hex)));

        Assert.Equal($"A map gives the key {key} twice.", e.Message);
    }

    // Why the rule is not left to CborConformanceMode.Strict: it compares encodings, so it reads all three. Should a
    // later runtime refuse them, this goes red and the comments that say Strict lets them through need changing.
    [Theory]
    [InlineData(IndefiniteText)]
    [InlineData(LongerInteger)]
    [InlineData(LongerNegative)]
    public void Strict_alone_lets_a_differently_encoded_repeat_through(string hex)
    {
        var reader = new CborReader(Convert.FromHexString(hex), CborConformanceMode.Strict);

        reader.SkipValue();

        Assert.Equal(0, reader.BytesRemaining);
    }

    [Theory]
    [InlineData("82A0A2616101616102")]   // [{}, {"a": 1, "a": 2}]: in an array
    [InlineData("A16178A2616101616102")] // {"x": {"a": 1, "a": 2}}: as a value
    [InlineData("C0A2616101616102")]     // 0({"a": 1, "a": 2}): under a tag
    [InlineData("BF616101616102FF")]     // {_ "a": 1, "a": 2}: an indefinite-length map
    public void A_repeated_key_is_refused_inside_arrays_values_and_tags(string hex) =>
        Assert.Throws<CborContentException>(() => MdocCbor.Reader(Convert.FromHexString(hex)));

    [Theory]
    [InlineData("A2613401" + "0402")]   // {"4": 1, 4: 2}: text and integer
    [InlineData("A2410401" + "0402")]   // {h'04': 1, 4: 2}: byte string and integer
    public void Keys_of_different_kinds_are_different_keys(string hex)
    {
        var reader = MdocCbor.Reader(Convert.FromHexString(hex));

        Assert.Equal(2, reader.ReadStartMap());
    }

    [Fact]
    public void Many_nested_tags_are_walked_without_running_out_of_stack()
    {
        // The reader limits how deep arrays and maps nest, not tags: a million tags before one value is well formed.
        // A walk that recursed once per tag would end the process with a stack overflow, which no catch can stop.
        var cbor = new byte[1_000_001];
        Array.Fill(cbor, (byte)0xC0);
        cbor[^1] = 0x01;

        var reader = MdocCbor.Reader(cbor);

        Assert.Equal(CborReaderState.Tag, reader.PeekState());
    }

    [Fact]
    public void Arrays_nested_past_the_readers_limit_are_refused_not_walked()
    {
        // 100 000 arrays deep: CborReader refuses nesting past its own limit, so the walk cannot recurse that far.
        var cbor = new byte[100_001];
        Array.Fill(cbor, (byte)0x81);
        cbor[^1] = 0x01;

        Assert.Throws<CborContentException>(() => MdocCbor.Reader(cbor));
    }

    // The two readers that ask MdocCbor for Strict say they do so to refuse text that is not UTF-8.
    [Fact]
    public void The_MSO_status_element_refuses_text_that_is_not_utf8()
    {
        // {"status_list": {"idx": 0, "uri": "\xC3\x28"}}
        var (references, problem) = MsoStatus.Read(
            Convert.FromHexString("A16B7374617475735F6C697374A263696478006375726962C328"));

        Assert.Empty(references);
        Assert.NotNull(problem);
    }

    [Fact]
    public void A_revocation_lists_claims_refuse_text_that_is_not_utf8() =>
        // {2: "\xC3\x28"}: the subject claim
        Assert.Throws<CborContentException>(() => MsoRevocationListClaims.Read(
            Convert.FromHexString("A10262C328"), RevocationListKind.StatusList, []));

    [Fact]
    public void A_byte_string_is_not_opened()
    {
        // {"a": h'A2616101616102'}: the bytes inside the byte string are a map with a repeated key. They are not read
        // here. Where they are CBOR, such as a tag 24 item, their own reader comes from MdocCbor.Reader.
        var reader = MdocCbor.Reader(Convert.FromHexString("A1616147A2616101616102"));

        Assert.Equal(1, reader.ReadStartMap());
    }

    [Fact]
    public void Strict_still_refuses_text_that_is_not_utf8() =>
        // {"a": "\xC3\x28"}
        Assert.Throws<CborContentException>(
            () => MdocCbor.Reader(Convert.FromHexString("A1616162C328"), CborConformanceMode.Strict));

    [Fact]
    public void The_reader_returned_starts_at_the_beginning()
    {
        var reader = MdocCbor.Reader(Convert.FromHexString("A1616101"));

        Assert.Equal(1, reader.ReadStartMap());
        Assert.Equal("a", reader.ReadTextString());
    }

    // How a source line makes a CborReader: by its name with or without the namespace. A target-typed new() is
    // caught only where it fills a CborReader variable as it is declared. Passed to a method, returned or assigned
    // to a variable declared earlier, it is not. The library has none of those today.
    private static readonly System.Text.RegularExpressions.Regex MakesReader = new(
        @"\bnew\s+(?:global::)?(?:System\.Formats\.Cbor\.)?CborReader\s*\(|\bCborReader\??\s+\w+\s*=\s*new\s*\(");

    [Theory]
    [InlineData("var r = new CborReader(b);")]
    [InlineData("var r = new System.Formats.Cbor.CborReader(b);")]
    [InlineData("var r = new global::System.Formats.Cbor.CborReader(b);")]
    [InlineData("CborReader r = new(b, CborConformanceMode.Lax);")]
    [InlineData("CborReader? r = new (b);")]
    public void The_guard_sees_each_way_of_making_a_reader(string line) => Assert.Matches(MakesReader, line);

    /// <summary>
    /// The library reads every map a presenter or an issuer sent through <see cref="MdocCbor.Reader"/>. A reader made
    /// any other way would skip the rule without any test of its path noticing. A file below may make its readers
    /// itself because each reads only arrays, single values or bytes this library made. Its count is fixed, so a
    /// reader added to one of these files fails here until someone has decided it reads no outside map.
    /// </summary>
    [Fact]
    public void No_library_source_makes_a_CborReader_except_where_allowed()
    {
        var src = Path.Combine(RepositoryRoot(), "src", "Tessio.Verifier.Core.Mdoc");
        Dictionary<string, (int Count, string Why)> allowed = new(StringComparer.Ordinal)
        {
            ["MdocCbor.cs"] = (2, "the owner"),
            ["CoseSign1Verification.cs"] = (1, "the crit array"),
            ["CoseX509.cs"] = (2, "an x5chain array or byte string"),
            ["DeviceMacVerifier.cs"] = (1, "the COSE_Mac0 array, whose header maps go to MdocCbor"),
            ["DeviceMacVerifier.Headers.cs"] = (2, "the crit array and single integers; the header maps go to MdocCbor"),
            ["EncryptionInfo.cs"] = (2, "an EncryptionInfo this library built, read back only to seal a test response"),
            ["IssuerAuthVerifier.cs"] = (1, "the x5t array"),
            ["MdocVerifier.cs"] = (1, "skipping one value to count it"),
            ["MsoRevocationListToken.cs"] = (2, "the COSE array and a type value"),
            ["ReaderAuthentication.cs"] = (1, "the tag and array of a COSE_Sign1"),
        };
        var obj = $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}";
        var offenders = Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains(obj, StringComparison.Ordinal))
            .Select(f => (File: Path.GetRelativePath(src, f), Count: MakesReader.Count(File.ReadAllText(f))))
            .Where(f => f.Count != (allowed.TryGetValue(f.File, out var a) ? a.Count : 0))
            .Select(f => $"{f.File} makes {f.Count}")
            .ToList();

        Assert.True(offenders.Count == 0,
            "These make a different number of CborReaders than allowed, so a map they read can give a key twice "
            + "unnoticed. Use MdocCbor.Reader. Only for a reader of no outside map, change the allowed count and "
            + "its reason: " + string.Join("; ", offenders));
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
