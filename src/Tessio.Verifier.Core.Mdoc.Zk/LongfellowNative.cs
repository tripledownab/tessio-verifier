using System.Runtime.InteropServices;

namespace Tessio.Verifier.Core.Mdoc.Zk;

// SPEC: the C API of longfellow-zk v0.9, lib/circuits/mdoc/mdoc_zk.h. The structs mirror its declarations
// field for field; a change there must be mirrored here.
internal static unsafe partial class LongfellowNative
{
    private const string Library = "mdoc";

    /// <summary>MDOC_VERIFIER_SUCCESS in MdocVerifierErrorCode.</summary>
    internal const int VerifierSuccess = 0;

    /// <summary>One claim the prover must have proved: RequestedAttribute in mdoc_zk.h.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct RequestedAttribute
    {
        public const int NameSpaceCapacity = 64;
        public const int IdCapacity = 32;
        public const int CborValueCapacity = 64;

        public fixed byte NameSpaceId[NameSpaceCapacity];
        public fixed byte Id[IdCapacity];
        public fixed byte CborValue[CborValueCapacity];
        public nuint NameSpaceLength;
        public nuint IdLength;
        public nuint CborValueLength;
    }

    /// <summary>ZkSpecStruct in mdoc_zk.h, read only for its attribute count.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct ZkSpec
    {
        public nint System;
        public fixed byte CircuitHash[65];
        public nuint NumAttributes;
        public nuint Version;
        public nuint BlockEncHash;
        public nuint BlockEncSig;
    }

    /// <summary>The library's static spec for this system and circuit hash, or null when it has none.</summary>
    [LibraryImport(Library, EntryPoint = "find_zk_spec", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ZkSpec* FindZkSpec(string system, string circuitHash);

    /// <summary>Writes the 32-byte identifier of a compressed circuit; returns nonzero on success.</summary>
    [LibraryImport(Library, EntryPoint = "circuit_id")]
    internal static partial int CircuitId(byte* id, byte* circuit, nuint circuitLength, ZkSpec* spec);

    /// <summary>
    /// Below proofs::LogLevel ERROR (1) in lib/util/log.h. The library prints a line when its level is at most
    /// the one set (lib/util/log.cc), so this prints none.
    /// </summary>
    internal const int LogLevelSilent = 0;

    /// <summary>proofs::set_log_level in lib/util/log.h, a C++ function, so bound by its mangled name.</summary>
    [LibraryImport(Library, EntryPoint = "_ZN6proofs13set_log_levelENS_8LogLevelE")]
    internal static partial void SetLogLevel(int level);

    [LibraryImport(Library, EntryPoint = "run_mdoc_verifier", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int RunMdocVerifier(
        byte* circuit, nuint circuitLength,
        string pkx, string pky,
        byte* transcript, nuint transcriptLength,
        RequestedAttribute* attributes, nuint attributeCount,
        string now,
        byte* proof, nuint proofLength,
        string docType,
        ZkSpec* spec);
}
