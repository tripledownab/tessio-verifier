using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc.Tests;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Zk.Tests;

/// <summary>
/// What belongs here: the real proof check, through Longfellow's library, against the zero knowledge example of
/// the age verification technical specification 1.1.0, Annex A, A.11. Each tampered case changes one input the
/// proof is bound to and must fail.
/// </summary>
/// <remarks>
/// Needs libmdoc.so, which tools/build-libmdoc.sh builds. The proof bytes are the example's, in
/// Fixtures/av-annex-a-a11-proof.bin. A proof check takes over a second, so the cases share one verifier.
/// </remarks>
public sealed class LongfellowProofVerifierTests : IClassFixture<LongfellowProofVerifierTests.VerifierFixture>
{
    private const string V7OneAttribute = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121";

    private static readonly DateTimeOffset Now = DateTimeOffset.Parse(AvZkVectors.Timestamp, System.Globalization.CultureInfo.InvariantCulture);

    private static readonly byte[] Proof = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "av-annex-a-a11-proof.bin"));

    private readonly LongfellowProofVerifier _zk;

    public LongfellowProofVerifierTests(VerifierFixture fixture) => _zk = fixture.Verifier;

    [LinuxX64Fact]
    public async Task The_specification_example_verifies_end_to_end()
    {
        var result = await Verify(AvZkResponses.Build(new() { Proof = Proof }));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Message)));
        Assert.Equal(true, ((Dictionary<string, object?>)result.DisclosedClaims[AvZkVectors.DocType])["age_over_18"]);
    }

    [LinuxX64Fact]
    public async Task A_disclosed_value_other_than_the_proved_one_fails()
    {
        var result = await Verify(AvZkResponses.Build(new() { Proof = Proof, Value = w => w.WriteBoolean(false) }));

        Assert.Equal(MdocErrorCodes.ZkProofInvalid, Assert.Single(result.Errors).Code);
    }

    [LinuxX64Fact]
    public async Task A_proof_with_one_byte_changed_fails()
    {
        var tampered = (byte[])Proof.Clone();
        tampered[tampered.Length / 2] ^= 1;

        var result = await Verify(AvZkResponses.Build(new() { Proof = tampered }));

        Assert.Equal(MdocErrorCodes.ZkProofInvalid, Assert.Single(result.Errors).Code);
    }

    [LinuxX64Fact]
    public async Task Another_session_transcript_fails()
    {
        var transcript = (byte[])AvZkVectors.SessionTranscript.Clone();
        transcript[^1] ^= 1;

        Assert.False(await _zk.VerifyAsync(Request() with { SessionTranscript = transcript }));
    }

    [LinuxX64Fact]
    public async Task Another_timestamp_fails()
    {
        // Within any clock skew, so only the proof can refuse it.
        Assert.False(await _zk.VerifyAsync(Request() with { Timestamp = "2026-02-05T08:45:00Z" }));
    }

    [LinuxX64Fact]
    public async Task Another_docType_fails()
    {
        Assert.False(await _zk.VerifyAsync(Request() with { DocType = "org.iso.18013.5.1.mDL" }));
    }

    [LinuxX64Fact]
    public async Task The_request_built_here_verifies_so_the_tampered_cases_fail_for_their_change()
    {
        Assert.True(await _zk.VerifyAsync(Request()));
    }

    [LinuxX64Fact]
    public void Both_carried_circuits_are_accepted_and_no_other()
    {
        Assert.True(_zk.AcceptsCircuit(AvZkVectors.CircuitHash));
        Assert.True(_zk.AcceptsCircuit(V7OneAttribute));
        Assert.False(_zk.AcceptsCircuit("b4bb6f01b7043f4f51d8302a30b36e3d4d2d0efc3c24557ab9212ad524a9764e"));
    }

    [LinuxX64Fact]
    public async Task A_disclosure_count_the_circuit_does_not_prove_is_refused()
    {
        var one = Request().Disclosures[0];

        Assert.False(await _zk.VerifyAsync(Request() with { Disclosures = [one, one with { ElementIdentifier = "age_over_21" }] }));
    }

    [LinuxX64Fact]
    public void A_carried_circuit_whose_bytes_do_not_match_its_hash_stops_the_verifier_loading()
    {
        var (name, bytes) = LongfellowProofVerifier.CarriedCircuits().First();
        var corrupted = (byte[])bytes.Clone();
        corrupted[^1] ^= 1;

        Assert.Throws<InvalidOperationException>(() => LongfellowProofVerifier.LoadCircuits([(name, corrupted)]));
        Assert.Single(LongfellowProofVerifier.LoadCircuits([(name, bytes)]));
    }

    [LinuxX64Fact]
    public void A_valid_circuit_carried_under_another_circuits_name_stops_the_verifier_loading()
    {
        // circuit_id succeeds on these bytes; only the comparison with the name's hash catches the swap.
        var circuits = LongfellowProofVerifier.CarriedCircuits().ToList();
        var v6 = circuits.Single(c => c.Name.EndsWith(AvZkVectors.CircuitHash, StringComparison.Ordinal));
        var v7 = circuits.Single(c => c.Name.EndsWith(V7OneAttribute, StringComparison.Ordinal));

        Assert.Throws<InvalidOperationException>(() => LongfellowProofVerifier.LoadCircuits([(v7.Name, v6.Bytes)]));
    }

    [LinuxX64Fact]
    public async Task The_proof_does_not_bind_the_namespace()
    {
        // Longfellow v0.9 uses the namespace only to check that all disclosures share one (sameNamespace in
        // lib/circuits/mdoc/mdoc_zk.cc); the circuit proves the element identifier and value, not where the MSO
        // filed them. Pinned so that a library which starts binding it is noticed and the claim keying revisited.
        var one = Request().Disclosures[0] with { NameSpace = "org.iso.18013.5.1" };

        Assert.True(await _zk.VerifyAsync(Request() with { Disclosures = [one] }));
    }

    [LinuxX64Theory]
    [InlineData(33, 1)]
    [InlineData(1, 65)]
    public async Task An_identifier_or_value_longer_than_the_library_holds_is_refused_not_thrown(int idBytes, int valueBytes)
    {
        var one = Request().Disclosures[0] with
        {
            ElementIdentifier = new string('i', idBytes),
            EncodedValue = new byte[valueBytes],
        };

        Assert.False(await _zk.VerifyAsync(Request() with { Disclosures = [one] }));
    }

    [LinuxX64Fact]
    public async Task A_transcript_past_the_libraries_limit_is_refused_instead_of_aborting_the_process()
    {
        // libmdoc aborts when transcript, docType and its framing reach 64 KiB (append_bytes_len); this one does.
        Assert.False(await _zk.VerifyAsync(Request() with { SessionTranscript = new byte[65_487] }));
    }

    [LinuxX64Fact]
    public void A_circuit_the_library_has_no_spec_for_stops_the_verifier_loading()
    {
        var (_, bytes) = LongfellowProofVerifier.CarriedCircuits().First();

        Assert.Throws<InvalidOperationException>(
            () => LongfellowProofVerifier.LoadCircuits([("longfellow-libzk-v1_9_1_1_1_" + new string('0', 64), bytes)]));
    }

    [LinuxX64Fact]
    public async Task A_namespace_longer_than_the_library_holds_is_refused_not_thrown()
    {
        var one = Request().Disclosures[0] with { NameSpace = new string('n', 65) };

        Assert.False(await _zk.VerifyAsync(Request() with { Disclosures = [one] }));
    }

    [LinuxX64Theory]
    [InlineData("00ab", "0xab")]
    [InlineData("0000", "0x")]
    [InlineData("ab00", "0xab00")]
    public void A_coordinate_is_written_as_the_library_reads_it(string bigEndian, string expected)
    {
        Assert.Equal(expected, LongfellowProofVerifier.Coordinate(Convert.FromHexString(bigEndian)));
    }

    private Task<VerificationResult> Verify(byte[] response)
    {
        var signer = X509CertificateLoader.LoadCertificate(AvZkVectors.DocumentSignerCertificate);
        var verifier = new MdocVerifier(
            new StaticTrustListResolver([signer.Subject], source: "av-example", trustAnchors: [signer], clock: new Fixed(Now)),
            new MdocVerifierOptions { ZkProofVerifier = _zk },
            new Fixed(Now));
        return verifier.VerifyAsync(
            new PresentedCredential { Format = MdocVerifier.Format, RawValue = Base64UrlEncoder.Encode(response) },
            new MdocVerificationContext { ExpectedDocType = AvZkVectors.DocType, SessionTranscript = AvZkVectors.SessionTranscript });
    }

    private static ZkProofRequest Request() => new()
    {
        ZkSystemId = AvZkVectors.ZkSystemId,
        CircuitHash = AvZkVectors.CircuitHash,
        DocType = AvZkVectors.DocType,
        Timestamp = AvZkVectors.Timestamp,
        SessionTranscript = AvZkVectors.SessionTranscript,
        IssuerKeyX = AvZkVectors.IssuerKeyX,
        IssuerKeyY = AvZkVectors.IssuerKeyY,
        Disclosures = [new ZkDisclosure(AvZkVectors.DocType, "age_over_18", new byte[] { 0xf5 })],
        Proof = Proof,
    };

    /// <summary>One verifier for the class: loading it checks both circuits, which is not free.</summary>
    public sealed class VerifierFixture : IDisposable
    {
        public LongfellowProofVerifier Verifier { get; } = new();

        public void Dispose() => Verifier.Dispose();
    }

    private sealed class Fixed(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
