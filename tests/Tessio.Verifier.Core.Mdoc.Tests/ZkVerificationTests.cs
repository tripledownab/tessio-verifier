using System.Formats.Cbor;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// What belongs here: everything <see cref="MdocVerifier"/> checks about a zero knowledge presentation before
/// and around the proof, with a stand in <see cref="IZkProofVerifier"/> that decides the proof's verdict.
/// </summary>
/// <remarks>
/// The presentation is the age verification technical specification 1.1.0, Annex A, A.11 example: its
/// zkSystemId, docType, timestamp, disclosure, msoX5chain and session transcript. The proof bytes are a
/// placeholder, because the stand in decides the proof's verdict.
/// </remarks>
public sealed class ZkVerificationTests : IDisposable
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse(AvZkVectors.Timestamp, System.Globalization.CultureInfo.InvariantCulture);

    private readonly X509Certificate2 _signer = X509CertificateLoader.LoadCertificate(AvZkVectors.DocumentSignerCertificate);

    public void Dispose() => _signer.Dispose();

    [Fact]
    public async Task A_presentation_the_proof_verifier_accepts_is_valid_and_discloses_its_items()
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(), zk);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => e.Message)));
        Assert.Equal(AvZkVectors.DocType, result.CredentialType);
        var claims = Assert.IsType<Dictionary<string, object?>>(result.DisclosedClaims[AvZkVectors.DocType]);
        Assert.Equal(true, claims["age_over_18"]);
        Assert.True(result.Issuer.Trusted);
    }

    [Fact]
    public async Task The_proof_verifier_gets_the_inputs_the_proof_is_bound_to()
    {
        var zk = new StandInProofVerifier();

        await Verify(AvZkResponses.Build(), zk);

        var request = Assert.Single(zk.Requests);
        Assert.Equal(AvZkVectors.ZkSystemId, request.ZkSystemId);
        Assert.Equal(AvZkVectors.CircuitHash, request.CircuitHash);
        Assert.Equal(AvZkVectors.DocType, request.DocType);
        Assert.Equal(AvZkVectors.Timestamp, request.Timestamp);
        Assert.Equal(AvZkVectors.SessionTranscript, request.SessionTranscript.ToArray());
        Assert.Equal(AvZkVectors.IssuerKeyX, request.IssuerKeyX.ToArray());
        Assert.Equal(AvZkVectors.IssuerKeyY, request.IssuerKeyY.ToArray());
        var disclosure = Assert.Single(request.Disclosures);
        Assert.Equal((AvZkVectors.DocType, "age_over_18"), (disclosure.NameSpace, disclosure.ElementIdentifier));
        Assert.Equal([0xf5], disclosure.EncodedValue.ToArray());
    }

    [Fact]
    public async Task A_proof_that_does_not_verify_fails_with_its_own_code()
    {
        var result = await Verify(AvZkResponses.Build(), new StandInProofVerifier(verdict: false));

        Assert.Equal(MdocErrorCodes.ZkProofInvalid, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData("longfellow-libzk-v1_7_1_4151_4096_8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121")]
    [InlineData("another-zk-system_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6")]
    [InlineData("longfellow-libzk-v1")]
    public async Task A_circuit_or_system_the_proof_verifier_does_not_accept_is_refused_before_the_proof(string zkSystemId)
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(new() { ZkSystemId = zkSystemId }), zk);

        Assert.Equal(MdocErrorCodes.ZkCircuitNotAccepted, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Fact]
    public async Task A_circuit_hash_in_uppercase_names_the_same_circuit()
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(new() { ZkSystemId = AvZkVectors.ZkSystemId.ToUpperInvariant().Replace("LONGFELLOW-LIBZK-V1", "longfellow-libzk-v1", StringComparison.Ordinal) }), zk);

        Assert.True(result.IsValid);
        Assert.Equal(AvZkVectors.CircuitHash, Assert.Single(zk.Requests).CircuitHash);
    }

    [Fact]
    public async Task A_docType_other_than_the_requested_one_is_refused()
    {
        var result = await Verify(AvZkResponses.Build(), new StandInProofVerifier(), expectedDocType: "org.iso.18013.5.1.mDL");

        Assert.Equal(MdocErrorCodes.DocTypeMismatch, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData(-6)]
    [InlineData(6)]
    [InlineData(-60 * 24 * 30)]
    public async Task A_timestamp_further_from_now_than_the_clock_skew_is_refused_before_the_proof(int minutes)
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(), zk, now: Now.AddMinutes(-minutes));

        Assert.Equal(MdocErrorCodes.ZkTimestampOutOfRange, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Theory]
    [InlineData(-4)]
    [InlineData(4)]
    public async Task A_timestamp_within_the_clock_skew_is_accepted(int minutes)
    {
        var result = await Verify(AvZkResponses.Build(), new StandInProofVerifier(), now: Now.AddMinutes(minutes));

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task An_untrusted_document_signer_is_refused_before_the_proof()
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(), zk, trust: new StaticTrustListResolver([], source: "nothing-trusted"));

        Assert.Equal(MdocErrorCodes.IssuerUntrusted, Assert.Single(result.Errors).Code);
        Assert.False(result.Issuer.Trusted);
        Assert.Empty(zk.Requests);
    }

    [Fact]
    public async Task Without_a_session_transcript_the_proof_cannot_be_checked()
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(), zk, omitTranscript: true);

        Assert.Equal(MdocErrorCodes.DeviceAuthInvalid, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Fact]
    public async Task OpenID4VP_transcript_inputs_without_a_session_transcript_are_refused_before_the_proof()
    {
        // A zero knowledge proof travels over the Digital Credentials API only, so the OpenID4VP redirect
        // transcript these inputs would build can never match it. Refused rather than tried.
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(), zk, omitTranscript: true, openId4VpInputs: true);

        Assert.Equal(MdocErrorCodes.DeviceAuthInvalid, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Fact]
    public async Task A_disclosed_value_the_converter_cannot_hold_is_a_structure_error_not_an_exception()
    {
        // 2^64 - 1 does not fit the converter's Int64; the verifier must answer, not throw.
        var result = await Verify(AvZkResponses.Build(new() { Value = w => w.WriteUInt64(ulong.MaxValue) }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData("2026-02-05T08:44:59Z ")]
    [InlineData("2026-02-05T08:44:59+00:00")]
    [InlineData("2026-02-05T08:44:59-14:00")]
    [InlineData("2026-02-05 08:44:59Z")]
    [InlineData("2026-02-05T08:44:59.000Z")]
    [InlineData("2026-02-05")]
    [InlineData("\uff12026-02-05T08:44:59Z")]
    public async Task A_timestamp_not_in_the_exact_form_the_circuit_compares_is_refused_before_the_proof(string timestamp)
    {
        // The circuit compares the first 20 bytes of the text with the MSO's validity window. Any other spelling of
        // an instant could pass the clock check here while proving validity at another time.
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(new() { Timestamp = timestamp }), zk);

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Fact]
    public async Task A_docType_with_a_NUL_is_refused_because_the_library_would_read_only_part_of_it()
    {
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(new() { DocType = AvZkVectors.DocType + "\0anything" }), zk, expectedDocType: null);

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Theory]
    [InlineData(255, true)]
    [InlineData(256, false)]
    public async Task A_docType_the_library_would_bind_as_the_mDL_docType_is_refused(int bytes, bool accepted)
    {
        // Longfellow binds a docType of 256 bytes or more as org.iso.18013.5.1.mDL, so it would be reported unproved.
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(new() { DocType = new string('d', bytes) }), zk, expectedDocType: null);

        Assert.Equal(accepted, result.IsValid);
        Assert.Equal(accepted, zk.Requests.Count == 1);
    }

    [Fact]
    public async Task A_text_value_that_is_not_valid_UTF8_is_a_structure_error()
    {
        // The library would see the raw bytes and the result would report their decoding; they must not differ.
        var result = await Verify(
            AvZkResponses.Build(new() { Value = w => w.WriteEncodedValue(new byte[] { 0x63, 0xED, 0xA0, 0x80 }) }),
            new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_value_nested_past_the_limit_is_a_structure_error_not_a_crash()
    {
        var result = await Verify(
            AvZkResponses.Build(new() { Value = w => Nest(w, CborValueConverter.MaxDepth + 1) }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_value_nested_to_the_limit_is_read()
    {
        var result = await Verify(
            AvZkResponses.Build(new() { Value = w => Nest(w, CborValueConverter.MaxDepth) }), new StandInProofVerifier());

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task Two_namespaces_are_a_structure_error_not_an_exception()
    {
        var result = await Verify(AvZkResponses.Build(new() { SecondNamespace = true }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_document_signer_on_a_curve_other_than_P256_is_refused_before_the_proof()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP384);
        var request = new CertificateRequest("CN=P-384 signer", key, System.Security.Cryptography.HashAlgorithmName.SHA384);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(1));
        var zk = new StandInProofVerifier();

        var result = await Verify(AvZkResponses.Build(new() { Chain = certificate.RawData }), zk);

        Assert.Equal(MdocErrorCodes.IssuerKeyUnresolvable, Assert.Single(result.Errors).Code);
        Assert.Empty(zk.Requests);
    }

    [Fact]
    public async Task An_empty_proof_is_a_structure_error()
    {
        var result = await Verify(AvZkResponses.Build(new() { Proof = [] }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task An_element_disclosed_twice_is_a_structure_error_not_an_exception()
    {
        var result = await Verify(AvZkResponses.Build(new() { Items = 2, SameIdentifier = true }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public async Task A_disclosure_of_other_than_one_to_four_items_is_a_structure_error(int items)
    {
        var result = await Verify(AvZkResponses.Build(new() { Items = items }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task Two_zero_knowledge_presentations_are_a_structure_error()
    {
        var result = await Verify(AvZkResponses.Build(new() { Presentations = 2 }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task A_presentation_without_its_certificate_chain_is_a_structure_error()
    {
        var result = await Verify(AvZkResponses.Build(new() { Chain = null }), new StandInProofVerifier());

        Assert.Equal(MdocErrorCodes.StructureInvalid, Assert.Single(result.Errors).Code);
    }

    private Task<VerificationResult> Verify(
        byte[] response,
        IZkProofVerifier zk,
        string? expectedDocType = AvZkVectors.DocType,
        DateTimeOffset? now = null,
        ITrustListResolver? trust = null,
        bool omitTranscript = false,
        bool openId4VpInputs = false)
    {
        var verifier = new MdocVerifier(
            trust ?? new StaticTrustListResolver([_signer.Subject], source: "av-example", trustAnchors: [_signer], clock: new Fixed(Now)),
            new MdocVerifierOptions { ZkProofVerifier = zk },
            new Fixed(now ?? Now));
        var context = new MdocVerificationContext
        {
            ExpectedDocType = expectedDocType,
            SessionTranscript = omitTranscript ? null : AvZkVectors.SessionTranscript,
            ClientId = openId4VpInputs ? "x509_san_dns:verifier.example" : null,
            Nonce = openId4VpInputs ? "nonce" : null,
            ResponseUri = openId4VpInputs ? "https://verifier.example/response" : null,
        };
        return verifier.VerifyAsync(new PresentedCredential { Format = MdocVerifier.Format, RawValue = Base64UrlEncoder.Encode(response) }, context);
    }

    private static void Nest(CborWriter writer, int levels)
    {
        // levels arrays inside one another, around a true: depth levels to the converter.
        for (var i = 0; i < levels; i++)
        {
            writer.WriteStartArray(1);
        }

        writer.WriteBoolean(true);
        for (var i = 0; i < levels; i++)
        {
            writer.WriteEndArray();
        }
    }

    private sealed class StandInProofVerifier(bool verdict = true) : IZkProofVerifier
    {
        public List<ZkProofRequest> Requests { get; } = [];

        public bool AcceptsCircuit(string circuitHash) => circuitHash == AvZkVectors.CircuitHash;

        public Task<bool> VerifyAsync(ZkProofRequest request, CancellationToken ct = default)
        {
            Requests.Add(request);
            return Task.FromResult(verdict);
        }
    }

    private sealed class Fixed(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
