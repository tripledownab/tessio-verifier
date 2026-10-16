using System.Reflection;
using System.Text;

namespace Tessio.Verifier.Core.Mdoc.Zk;

/// <summary>
/// Checks Longfellow (<c>longfellow-libzk-v1</c>) zero knowledge proofs of mdoc presentations with Google's
/// Longfellow ZK library, for the circuits this package carries: one disclosed element, versions 6 and 7.
/// </summary>
/// <remarks>
/// <para>
/// Set an instance on <see cref="MdocVerifierOptions.ZkProofVerifier"/>. Linux x64 with glibc only (not musl):
/// the package ships <c>libmdoc.so</c>. The host needs OpenSSL 3, zstd, zlib, glibc 2.32 or later and libstdc++
/// from GCC 11 or later, the newest versions the library's symbols name (<c>objdump -T</c>).
/// </para>
/// <para>
/// The circuits carried are Longfellow's one element circuits, versions 6 and 7, which the EU age verification
/// apps use. The age verification profile leaves the set of accepted circuits to its scheme owner, published
/// separately (Annex A, A.8); to accept fewer, wrap this class in an <see cref="IZkProofVerifier"/> whose
/// <see cref="IZkProofVerifier.AcceptsCircuit"/> narrows it.
/// </para>
/// <para>
/// A proof check is CPU and memory heavy, because the library decompresses the circuit on every call. At most
/// <c>maxConcurrentProofs</c> run at a time, and the rest wait without limit, so bound the wait with the
/// cancellation token passed to <see cref="MdocVerifier.VerifyAsync"/>. Size the limit to the memory available.
/// </para>
/// <para>
/// Constructing one sets Longfellow's process wide log level to errors only; it logs every proof otherwise.
/// </para>
/// </remarks>
public sealed class LongfellowProofVerifier : IZkProofVerifier, IDisposable
{
    private readonly Dictionary<string, Circuit> _circuits;
    private readonly SemaphoreSlim _gate;

    /// <summary>Loads the carried circuits and checks each against its hash.</summary>
    /// <param name="maxConcurrentProofs">How many proofs may be checked at the same time. Defaults to 2.</param>
    /// <exception cref="InvalidOperationException">A carried circuit does not match its hash.</exception>
    /// <exception cref="DllNotFoundException">libmdoc.so, or a library it needs, cannot be loaded.</exception>
    public LongfellowProofVerifier(int maxConcurrentProofs = 2)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConcurrentProofs, 1);
        _gate = new SemaphoreSlim(maxConcurrentProofs, maxConcurrentProofs);
        LongfellowNative.SetLogLevel(LongfellowNative.LogLevelError);
        _circuits = LoadCircuits(CarriedCircuits());
        SystemIds = [.. _circuits.Values.Select(c => c.SystemId).Order(StringComparer.Ordinal)];
    }

    /// <inheritdoc />
    public bool AcceptsCircuit(string circuitHash) => _circuits.ContainsKey(circuitHash);

    /// <summary>
    /// The <c>zkSystemId</c> of every circuit this verifier accepts, in ordinal order: what to pass to
    /// <see cref="ZkRequest(IEnumerable{string})"/> so a wallet only proves with a circuit that can be checked here.
    /// </summary>
    public IReadOnlyList<string> SystemIds { get; }

    /// <inheritdoc />
    public async Task<bool> VerifyAsync(ZkProofRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!_circuits.TryGetValue(request.CircuitHash, out var circuit) || !Fits(request, circuit))
        {
            return false;
        }

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await Task.Run(() => Run(request, circuit), ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose() => _gate.Dispose();

    /// <summary>A carried circuit, its <c>zkSystemId</c>, the library's static spec for it and how many disclosures it proves.</summary>
    internal sealed record Circuit(string SystemId, byte[] Bytes, nint Spec, int Attributes);

    private const int TranscriptFraming = 64;

    // The library holds at most this many bytes per field, so a longer one can never be what was proved. The
    // count matters more: given more disclosures than its circuit proves, libmdoc aborts the process on an
    // assertion before it reaches its own attribute count check, so this guard is what keeps a wallet from
    // killing the host.
    // The library also aborts when the transcript, the docType and its own framing exceed 64 KiB together
    // (append_bytes_len in mdoc_witness.h); TranscriptFraming covers the framing with room to spare.
    private static bool Fits(ZkProofRequest request, Circuit circuit) =>
        request.SessionTranscript.Length + Encoding.UTF8.GetByteCount(request.DocType) + TranscriptFraming < 65536
        && request.Disclosures.Count == circuit.Attributes
        && request.Disclosures.All(d =>
            Encoding.UTF8.GetByteCount(d.NameSpace) <= LongfellowNative.RequestedAttribute.NameSpaceCapacity
            && Encoding.UTF8.GetByteCount(d.ElementIdentifier) <= LongfellowNative.RequestedAttribute.IdCapacity
            && d.EncodedValue.Length <= LongfellowNative.RequestedAttribute.CborValueCapacity);

    private static unsafe bool Run(ZkProofRequest request, Circuit circuit)
    {
        var attributes = new LongfellowNative.RequestedAttribute[request.Disclosures.Count];
        for (var i = 0; i < attributes.Length; i++)
        {
            attributes[i] = Attribute(request.Disclosures[i]);
        }

        fixed (byte* circuitBytes = circuit.Bytes)
        fixed (byte* transcript = request.SessionTranscript.Span)
        fixed (byte* proof = request.Proof.Span)
        fixed (LongfellowNative.RequestedAttribute* attributesPtr = attributes)
        {
            return LongfellowNative.RunMdocVerifier(
                circuitBytes, (nuint)circuit.Bytes.Length,
                Coordinate(request.IssuerKeyX.Span), Coordinate(request.IssuerKeyY.Span),
                transcript, (nuint)request.SessionTranscript.Length,
                attributesPtr, (nuint)attributes.Length,
                request.Timestamp,
                proof, (nuint)request.Proof.Length,
                request.DocType,
                (LongfellowNative.ZkSpec*)circuit.Spec) == LongfellowNative.VerifierSuccess;
        }
    }

    private static unsafe LongfellowNative.RequestedAttribute Attribute(ZkDisclosure disclosure)
    {
        var attribute = default(LongfellowNative.RequestedAttribute);
        var nameSpace = Encoding.UTF8.GetBytes(disclosure.NameSpace);
        var id = Encoding.UTF8.GetBytes(disclosure.ElementIdentifier);
        nameSpace.CopyTo(new Span<byte>(attribute.NameSpaceId, LongfellowNative.RequestedAttribute.NameSpaceCapacity));
        id.CopyTo(new Span<byte>(attribute.Id, LongfellowNative.RequestedAttribute.IdCapacity));
        disclosure.EncodedValue.Span.CopyTo(new Span<byte>(attribute.CborValue, LongfellowNative.RequestedAttribute.CborValueCapacity));
        attribute.NameSpaceLength = (nuint)nameSpace.Length;
        attribute.IdLength = (nuint)id.Length;
        attribute.CborValueLength = (nuint)disclosure.EncodedValue.Length;
        return attribute;
    }

    // The library parses a coordinate as "0x" and the hex of the number, as Longfellow's reference verifier
    // writes it: Go's big.Int.Bytes, which drops leading zero bytes.
    internal static string Coordinate(ReadOnlySpan<byte> bigEndian)
    {
        var significant = bigEndian.TrimStart((byte)0);
        return "0x" + Convert.ToHexString(significant).ToLowerInvariant();
    }

    /// <summary>The circuits embedded in this assembly, each named by its <c>zkSystemId</c>.</summary>
    internal static IEnumerable<(string Name, byte[] Bytes)> CarriedCircuits()
    {
        var assembly = typeof(LongfellowProofVerifier).Assembly;
        return assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(LongfellowSystemId.System + "_", StringComparison.Ordinal))
            .Select(n => (n, Read(assembly, n)));
    }

    /// <summary>
    /// Indexes circuits by hash. Any one of these refuses a circuit: a name that is not a <c>zkSystemId</c> in its
    /// one spelling, parameters in the name that differ from the library's spec for the hash, bytes that do not
    /// match the hash. The name is what a request offers, so it must say what the library will check.
    /// </summary>
    internal static unsafe Dictionary<string, Circuit> LoadCircuits(IEnumerable<(string Name, byte[] Bytes)> sources)
    {
        Dictionary<string, Circuit> circuits = new(StringComparer.Ordinal);
        foreach (var (name, bytes) in sources)
        {
            if (LongfellowSystemId.Parse(name) is not { IsCanonical: true } id)
            {
                throw new InvalidOperationException($"The carried circuit {name} is not named by a zkSystemId in its one spelling.");
            }

            var hash = id.CircuitHash;
            var spec = LongfellowNative.FindZkSpec(LongfellowSystemId.System, hash);
            if (spec is null)
            {
                throw new InvalidOperationException($"The Longfellow library has no spec for the carried circuit {name}.");
            }

            if ((nuint)id.Version != spec->Version || (nuint)id.NumAttributes != spec->NumAttributes
                || (nuint)id.BlockEncHash != spec->BlockEncHash || (nuint)id.BlockEncSig != spec->BlockEncSig)
            {
                throw new InvalidOperationException($"The carried circuit {name} names parameters its library spec does not have.");
            }

            var circuitId = new byte[32];
            fixed (byte* idPtr = circuitId)
            fixed (byte* circuitPtr = bytes)
            {
                // A failed circuit_id leaves the id zero, which the comparison refuses as well.
                _ = LongfellowNative.CircuitId(idPtr, circuitPtr, (nuint)bytes.Length, spec);
                if (!string.Equals(Convert.ToHexString(circuitId).ToLowerInvariant(), hash, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException($"The carried circuit {name} does not match its hash.");
                }
            }

            circuits[hash] = new Circuit(name, bytes, (nint)spec, checked((int)spec->NumAttributes));
        }

        return circuits;
    }

    private static byte[] Read(Assembly assembly, string name)
    {
        using var stream = assembly.GetManifestResourceStream(name)!;
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }
}
