namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// What belongs here: which presented zkSystemId spellings name a circuit, tested on the parser itself. Through
/// MdocVerifier a malformed spelling is also refused by the proof verifier's AcceptsCircuit, which would hide a
/// parser that let it through.
/// </summary>
public sealed class LongfellowSystemIdTests
{
    private const string Hash = "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6";

    [Theory]
    [InlineData("longfellow-libzk-v1_6_1_4096_2945_" + Hash)]
    [InlineData(Hash)]
    [InlineData("137E5A75CE72735A37C8A72DA1A8A0A5DF8D13365C2AE3D2C2BD6A0E7197C7C6")]
    public void A_Longfellow_identifier_or_a_bare_hash_names_the_circuit_in_lowercase(string zkSystemId)
    {
        Assert.Equal(Hash, LongfellowSystemId.CircuitHashNamedBy(zkSystemId));
    }

    [Theory]
    [InlineData("137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c")]
    [InlineData("137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c66")]
    [InlineData("137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7cg")]
    [InlineData(" 137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c")]
    [InlineData("")]
    [InlineData(null)]
    public void Anything_else_names_no_circuit(string? zkSystemId)
    {
        Assert.Null(LongfellowSystemId.CircuitHashNamedBy(zkSystemId));
    }
}
