namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Checks the proof of a zero knowledge mdoc presentation. <see cref="MdocVerifier"/> does everything else
/// first: it reads the presentation, checks the docType, bounds the wallet's timestamp against its own
/// clock, takes the issuer key from the document signer certificate and asks the trust seam about that
/// certificate's chain. Only a presentation that passes all of that reaches <see cref="VerifyAsync"/>.
/// </summary>
/// <remarks>
/// Set one on <see cref="MdocVerifierOptions.ZkProofVerifier"/> to accept zero knowledge presentations.
/// Without one, a response made only of them fails with <see cref="MdocErrorCodes.ZkPresentationUnsupported"/>.
/// A Longfellow proof does not bind the namespace of a disclosed element, only its identifier and value, so the
/// namespace a verified result reports is the one the presentation states.
/// </remarks>
public interface IZkProofVerifier
{
    /// <summary>
    /// Whether proofs made with the circuit of this hash are accepted. The hash is lowercase hex, the
    /// last part of a <c>zkSystemId</c> such as <c>longfellow-libzk-v1_6_1_4096_2945_137e…</c>.
    /// </summary>
    bool AcceptsCircuit(string circuitHash);

    /// <summary>Whether the proof verifies for these inputs. A proof that does not verify returns false.</summary>
    Task<bool> VerifyAsync(ZkProofRequest request, CancellationToken ct = default);
}

/// <summary>The inputs a zero knowledge proof of an mdoc is checked against.</summary>
public sealed record ZkProofRequest
{
    /// <summary>
    /// The <c>zkSystemId</c> the presentation names, exactly as sent: the Longfellow form or a bare circuit hash.
    /// Read the circuit from <see cref="CircuitHash"/>, not by parsing this.
    /// </summary>
    public required string ZkSystemId { get; init; }

    /// <summary>The circuit hash taken from <see cref="ZkSystemId"/>, lowercase hex.</summary>
    public required string CircuitHash { get; init; }

    public required string DocType { get; init; }

    /// <summary>The wallet's timestamp exactly as transported, for example <c>2026-02-05T08:44:59Z</c>.</summary>
    public required string Timestamp { get; init; }

    /// <summary>The session transcript the presentation is bound to, as CBOR.</summary>
    public required ReadOnlyMemory<byte> SessionTranscript { get; init; }

    /// <summary>The x coordinate of the document signer's P-256 public key, big endian, 32 bytes.</summary>
    public required ReadOnlyMemory<byte> IssuerKeyX { get; init; }

    /// <summary>The y coordinate of the document signer's P-256 public key, big endian, 32 bytes.</summary>
    public required ReadOnlyMemory<byte> IssuerKeyY { get; init; }

    /// <summary>The disclosed elements the proof is about, in the order the presentation lists them.</summary>
    public required IReadOnlyList<ZkDisclosure> Disclosures { get; init; }

    public required ReadOnlyMemory<byte> Proof { get; init; }
}

/// <summary>One disclosed element: its namespace, its identifier and its value as encoded CBOR.</summary>
public sealed record ZkDisclosure(string NameSpace, string ElementIdentifier, ReadOnlyMemory<byte> EncodedValue);
