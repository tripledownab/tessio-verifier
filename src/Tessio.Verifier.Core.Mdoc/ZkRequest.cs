using System.Collections.Immutable;
using System.Formats.Cbor;

namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Asks the wallet for a zero knowledge proof of the requested elements: the <c>zkRequest</c> a request carries
/// in its ItemsRequest's <c>requestInfo</c>.
/// </summary>
/// <remarks>
/// Pass one to <see cref="Iso18013AnnexC.CreateRequest(string, string, IReadOnlyList{string}, ZkRequest)"/> or
/// <see cref="Iso18013AnnexC.CreateSignedRequest(string, string, IReadOnlyList{string}, string, MdocReaderKey, byte[], ZkRequest)"/>.
/// The age verification profile carries zero knowledge proofs over the Digital Credentials API only (technical
/// specification 1.1.0, Annex A, A.6), so no other transport takes one.
/// </remarks>
// SPEC: Annex A, A.8 has the request "follow the ZkSystemSpec mechanism defined in ISO/IEC 18013-5 (Second
// Edition), Section 10.2.7", a draft this library could not read. The shape written is the one the A.11 example,
// which is informative only, shows:
//   requestInfo = {"zkRequest": {"systemSpecs": [ZkSystemSpec, ...], "zkRequired": bool}}
//   ZkSystemSpec = {"zkSystemId": tstr, "system": tstr, "params": {"version": uint, "circuit_hash": tstr,
//                   "num_attributes": uint, "block_enc_hash": uint, "block_enc_sig": uint}}
public sealed class ZkRequest
{
    /// <summary>Asks for a proof made with one of the circuits <paramref name="systemIds"/> names.</summary>
    /// <param name="systemIds">
    /// The <c>zkSystemId</c> of each circuit the wallet may prove with, for example
    /// <c>longfellow-libzk-v1_6_1_4096_2945_137e…</c>. Offer only circuits the verifier accepts; with the zero
    /// knowledge package that is <c>LongfellowProofVerifier.SystemIds</c>. Annex A, A.8 puts one system in scope,
    /// <c>longfellow-libzk-v1</c>. Each identifier must name it in the form the A.11 example and the Longfellow
    /// wallet libraries use, with a lowercase hash, because the circuit parameters written beside it are read from it.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="systemIds"/> or one of its items is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="systemIds"/> is empty, holds an identifier not of that form or names one circuit twice.
    /// </exception>
    public ZkRequest(IEnumerable<string> systemIds)
    {
        ArgumentNullException.ThrowIfNull(systemIds);
        var ids = systemIds.ToImmutableArray();
        if (ids.IsEmpty)
        {
            throw new ArgumentException("A zero knowledge request needs at least one zkSystemId.", nameof(systemIds));
        }

        List<LongfellowSystemId> specs = [];
        foreach (var id in ids)
        {
            ArgumentNullException.ThrowIfNull(id, nameof(systemIds));
            if (LongfellowSystemId.Parse(id) is not { IsCanonical: true } spec)
            {
                throw new ArgumentException(
                    $"'{id}' is not a {LongfellowSystemId.System} zkSystemId in the form the A.11 example uses.", nameof(systemIds));
            }

            if (specs.Exists(s => s.CircuitHash == spec.CircuitHash))
            {
                throw new ArgumentException($"The circuit of '{id}' is offered twice.", nameof(systemIds));
            }

            specs.Add(spec);
        }

        _specs = [.. specs];
    }

    // The offered circuits in the order given, read once when constructed.
    private readonly ImmutableArray<LongfellowSystemId> _specs;

    /// <summary>
    /// <c>zkRequired</c>: whether the wallet must answer with a proof. Leave it false, the default, for the age
    /// verification profile: its Annex A, A.6 has a plain mdoc presentation answer where the device cannot make a
    /// proof, and A.9 says "A Relying Party SHALL NOT reject a presentation solely on the ground that it uses the
    /// plain ISO mDoc fallback mechanism".
    /// </summary>
    public bool Required { get; init; }

    /// <summary>
    /// The encoded <c>zkRequest</c> value for a request of <paramref name="elementCount"/> elements. A Longfellow
    /// circuit proves a fixed number of disclosures, so at least one offered circuit must prove that many.
    /// </summary>
    internal byte[] Encode(int elementCount, string parameterName)
    {
        if (!_specs.Any(s => s.NumAttributes == elementCount))
        {
            throw new ArgumentException(
                $"No offered circuit proves {elementCount} elements, so no wallet could answer with a proof.", parameterName);
        }

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteTextString("systemSpecs");
        writer.WriteStartArray(_specs.Length);
        foreach (var spec in _specs)
        {
            WriteSystemSpec(writer, spec);
        }

        writer.WriteEndArray();
        writer.WriteTextString("zkRequired");
        writer.WriteBoolean(Required);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static void WriteSystemSpec(CborWriter writer, LongfellowSystemId spec)
    {
        writer.WriteStartMap(3);
        writer.WriteTextString("zkSystemId");
        writer.WriteTextString(spec.Value);
        writer.WriteTextString("system");
        writer.WriteTextString(LongfellowSystemId.System);
        writer.WriteTextString("params");
        writer.WriteStartMap(5);
        writer.WriteTextString("version");
        writer.WriteInt32(spec.Version);
        writer.WriteTextString("circuit_hash");
        writer.WriteTextString(spec.CircuitHash);
        writer.WriteTextString("num_attributes");
        writer.WriteInt32(spec.NumAttributes);
        writer.WriteTextString("block_enc_hash");
        writer.WriteInt32(spec.BlockEncHash);
        writer.WriteTextString("block_enc_sig");
        writer.WriteInt32(spec.BlockEncSig);
        writer.WriteEndMap();
        writer.WriteEndMap();
    }
}
