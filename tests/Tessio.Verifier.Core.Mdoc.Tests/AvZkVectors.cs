namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// The zero knowledge response example of the age verification technical specification 1.1.0, Annex A, A.11
/// (Digital Credentials API transport). Externally produced bytes: NEVER regenerate them.
/// </summary>
/// <remarks>
/// The document signer certificate is the one in the example's <c>msoX5chain</c>: CN=Age Verification DS - 001,
/// issued by the reference implementation's Age Verification Issuer CA 01, valid 2025-07-01 to 2026-09-24.
/// </remarks>
internal static class AvZkVectors
{
    public const string DocType = "eu.europa.ec.av.1";

    public const string ZkSystemId =
        "longfellow-libzk-v1_6_1_4096_2945_137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6";

    public const string CircuitHash = "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6";

    public const string Timestamp = "2026-02-05T08:44:59Z";

    /// <summary>[null, null, ["dcapi", h'2afa…']], as the example gives it.</summary>
    public static readonly byte[] SessionTranscript = WrappedHex.Decode("""
        83f6f68265646361706958202afa2a72d5d109d8dad677ecdeec5173cf386f028602a2328ad94a728da8a994
        """);

    public static readonly byte[] DocumentSignerCertificate = WrappedHex.Decode("""
        308202bd30820263a00302010202147076c1d015eabc3fd67b3fd7aa78a6cfe3cd2f85300a06082a8648ce3d04030230
        693126302406035504030c1d41676520566572696669636174696f6e2049737375657220434120303131323030060355
        040a0c2941676520566572696669636174696f6e205265666572656e636520496d706c656d656e746174696f6e310b30
        09060355040613024555301e170d3235303730313130353731315a170d3236303932343130353731305a306531223020
        06035504030c1941676520566572696669636174696f6e204453202d2030303131323030060355040a0c294167652056
        6572696669636174696f6e205265666572656e636520496d706c656d656e746174696f6e310b30090603550406130245
        553059301306072a8648ce3d020106082a8648ce3d030107034200046789e96e797e2e04f7f3cbb54a12410412410db0
        00fb6d63dc977d8b5d35a4f93b71f297d9d308ba2e955e8563afa0604833aae10ecb1aaefbe4159b5b8b9057a381ec30
        81e9301f0603551d23041830168014cb7095804c991edc6d0b7cfeebe041ca22542ed830160603551d250101ff040c30
        0a06082b8102020000010230440603551d1f043d303b3039a037a035863368747470733a2f2f6973737565722e616765
        766572696669636174696f6e2e6465762f706b692f45555f43415f30312e63726c301d0603551d0e04160414ff1bba97
        b2ca7ef5aea3301486f1fbc98b4598fa300e0603551d0f0101ff04040302078030390603551d12043230300603551d12
        04293027822568747470733a2f2f636f6d6d697373696f6e2e6575726f70612e65752f696e6465785f656e300a06082a
        8648ce3d040302034800304502204aaf5b867e6f1202e0f4924de8b689319471f9ce6b3b9cb7355fa68a014e26370221
        00ddb326b3c089df558f5732eaaa5e87c0d5d5140624602f3598afdabf180db66a
        """);

    /// <summary>The document signer's public key coordinates, big endian.</summary>
    public static readonly byte[] IssuerKeyX = Convert.FromHexString("6789e96e797e2e04f7f3cbb54a12410412410db000fb6d63dc977d8b5d35a4f9");

    public static readonly byte[] IssuerKeyY = Convert.FromHexString("3b71f297d9d308ba2e955e8563afa0604833aae10ecb1aaefbe4159b5b8b9057");
}
