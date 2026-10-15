using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core.Mdoc.Tests;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Zk.Tests;

/// <summary>
/// What belongs here: the real proof check, through Longfellow's library, for each carried circuit. Version 6 is
/// checked against the zero knowledge example of the age verification technical specification 1.1.0, Annex A,
/// A.11; version 7 against a proof made from Longfellow's own example mdoc. A case that changes one input the
/// proof binds must fail. A test pins that the proof does not bind the namespace. A case giving an input the library
/// cannot hold must be refused before the library runs.
/// </summary>
/// <remarks>
/// Needs libmdoc.so, which tools/build-libmdoc.sh builds. The A.11 proof is in Fixtures/av-annex-a-a11-proof.bin;
/// the version 7 proof is in Fixtures/longfellow-mdoc-tests-15-v7-proof.bin, made by Fixtures/make-v7-proof.cc.
/// Loading a verifier checks both circuits, so the cases share one.
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
    public async Task A_genuine_v7_proof_verifies()
    {
        Assert.True(await _zk.VerifyAsync(V7Request()));
    }

    [LinuxX64Fact]
    public async Task A_v7_proof_with_one_byte_changed_fails()
    {
        var request = V7Request();
        var tampered = request.Proof.ToArray();
        tampered[tampered.Length / 2] ^= 1;

        Assert.False(await _zk.VerifyAsync(request with { Proof = tampered }));
    }

    [LinuxX64Fact]
    public async Task A_v7_proof_for_another_timestamp_fails()
    {
        Assert.False(await _zk.VerifyAsync(V7Request() with { Timestamp = "2026-01-15T09:00:01Z" }));
    }

    [LinuxX64Fact]
    public async Task A_v7_proof_for_another_value_fails()
    {
        var request = V7Request();

        Assert.False(await _zk.VerifyAsync(request with { Disclosures = [request.Disclosures[0] with { EncodedValue = new byte[] { 0xf4 } }] }));
    }

    [LinuxX64Fact]
    public async Task A_v7_proof_for_another_docType_fails()
    {
        Assert.False(await _zk.VerifyAsync(V7Request() with { DocType = "org.iso.18013.5.1.mDL" }));
    }

    [LinuxX64Fact]
    public async Task A_v7_proof_for_another_session_transcript_fails()
    {
        var request = V7Request();
        var transcript = request.SessionTranscript.ToArray();
        transcript[^1] ^= 1;

        Assert.False(await _zk.VerifyAsync(request with { SessionTranscript = transcript }));
    }

    [LinuxX64Theory]
    [InlineData(6)]
    [InlineData(7)]
    public async Task A_proof_checked_against_another_element_identifier_fails(int version)
    {
        var request = version == 6 ? Request() : V7Request();
        var claimed = request.Disclosures[0] with { ElementIdentifier = "age_over_21" };

        Assert.False(await _zk.VerifyAsync(request with { Disclosures = [claimed] }));
    }

    [LinuxX64Theory]
    [InlineData(6)]
    [InlineData(7)]
    public async Task A_proof_checked_against_another_issuer_key_fails(int version)
    {
        // The issuer key is what makes a proof mean that this issuer signed the mdoc. Each request gets the other
        // example's key, a valid P-256 point that did not sign this proof's mdoc.
        var request = version == 6 ? Request() with { IssuerKeyX = V7Request().IssuerKeyX, IssuerKeyY = V7Request().IssuerKeyY }
            : V7Request() with { IssuerKeyX = AvZkVectors.IssuerKeyX, IssuerKeyY = AvZkVectors.IssuerKeyY };

        Assert.False(await _zk.VerifyAsync(request));
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

    // A v7 proof made from Longfellow's own EU age verification example, mdoc_tests[15] in its mdoc_examples.h,
    // by Fixtures/make-v7-proof.cc. The inputs are that example's.
    private static ZkProofRequest V7Request() => new()
    {
        ZkSystemId = "longfellow-libzk-v1_7_1_4151_4096_" + V7OneAttribute,
        CircuitHash = V7OneAttribute,
        DocType = "eu.europa.ec.av.1",
        Timestamp = "2026-01-15T09:00:00Z",
        SessionTranscript = Convert.FromHexString(
            "83f6f6847142726f7773657248616e646f766572763158200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            + "5835a363636174016474797065016764657461696c73a1676261736555726c77687474703a2f2f72656c79696e6770617274792e636f6d"
            + "58202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"),
        IssuerKeyX = Convert.FromHexString("b4682ec20e06e8df840b5dd32959798ab20c544d4da50109ff4684d06fd261fc"),
        IssuerKeyY = Convert.FromHexString("f6f8e9a811911329a5f653fcec5990092c91a65bc1695d291cd51de9c94e7db7"),
        Disclosures = [new ZkDisclosure("eu.europa.ec.av.1", "age_over_18", new byte[] { 0xf5 })],
        Proof = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "longfellow-mdoc-tests-15-v7-proof.bin")),
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
