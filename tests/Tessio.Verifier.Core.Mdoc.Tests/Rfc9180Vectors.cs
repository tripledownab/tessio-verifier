namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// RFC 9180 Appendix A.3.1 test vectors: base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
/// AES-128-GCM, exactly the suite <c>Hpke</c> implements. Copied from the RFC Editor's canonical
/// text (https://www.rfc-editor.org/rfc/rfc9180.txt). Externally produced bytes: NEVER regenerate.
/// Only the sequence-0 encryption is included, because the single-message API has no sequence
/// counter; the vector's remaining encryptions exercise machinery that deliberately does not exist.
/// </summary>
internal static class Rfc9180Vectors
{
    /// <summary>A.3.1 <c>info</c>: the ASCII of "Ode on a Grecian Urn".</summary>
    public const string InfoHex = "4f6465206f6e2061204772656369616e2055726e";

    /// <summary>A.3.1 <c>skEm</c>: the sender's ephemeral private scalar.</summary>
    public const string SkEmHex = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";

    /// <summary>A.3.1 <c>pkEm</c>: the sender's ephemeral public key, uncompressed.</summary>
    public const string PkEmHex =
        """
        04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b32
        5ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4
        """;

    /// <summary>A.3.1 <c>skRm</c>: the recipient's private scalar.</summary>
    public const string SkRmHex = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";

    /// <summary>A.3.1 <c>pkRm</c>: the recipient's public key, uncompressed.</summary>
    public const string PkRmHex =
        """
        04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f70
        6a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0
        """;

    /// <summary>A.3.1 <c>enc</c>: the encapsulated key, which this KEM defines as pkEm's bytes.</summary>
    public const string EncHex =
        """
        04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325
        ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4
        """;

    /// <summary>A.3.1.1 sequence 0 <c>pt</c>: the ASCII of "Beauty is truth, truth beauty".</summary>
    public const string PlaintextHex = "4265617574792069732074727574682c20747275746820626561757479";

    /// <summary>A.3.1.1 sequence 0 <c>aad</c>: the ASCII of "Count-0".</summary>
    public const string AadHex = "436f756e742d30";

    /// <summary>A.3.1.1 sequence 0 <c>ct</c>, with the 16-byte GCM tag appended.</summary>
    public const string CiphertextHex =
        """
        5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f
        9076ac232e3ab2523f39513434
        """;

    public static byte[] Info => WrappedHex.Decode(InfoHex);

    public static byte[] SkEm => WrappedHex.Decode(SkEmHex);

    public static byte[] PkEm => WrappedHex.Decode(PkEmHex);

    public static byte[] SkRm => WrappedHex.Decode(SkRmHex);

    public static byte[] PkRm => WrappedHex.Decode(PkRmHex);

    public static byte[] Enc => WrappedHex.Decode(EncHex);

    public static byte[] Plaintext => WrappedHex.Decode(PlaintextHex);

    public static byte[] Aad => WrappedHex.Decode(AadHex);

    public static byte[] Ciphertext => WrappedHex.Decode(CiphertextHex);
}
