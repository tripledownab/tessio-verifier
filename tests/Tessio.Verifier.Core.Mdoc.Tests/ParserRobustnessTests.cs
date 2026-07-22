using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Mutation-based robustness: the parser and verifier consume attacker-controlled bytes, so every
/// mutated input must either parse, throw <see cref="MdocProcessingException"/> or produce an
/// invalid <see cref="VerificationResult"/>. Any other exception type is a robustness bug. Seeded
/// for determinism; a failure prints the seed and iteration for reproduction.
/// </summary>
public sealed class ParserRobustnessTests
{
    private const int Iterations = 400;
    private const int Seed = 20260722;

    private static byte[] Mutate(byte[] source, Random rng)
    {
        var mutated = (byte[])source.Clone();
        switch (rng.Next(4))
        {
            case 0: // flip one random byte
                mutated[rng.Next(mutated.Length)] ^= (byte)(1 + rng.Next(255));
                return mutated;
            case 1: // truncate
                return mutated[..rng.Next(mutated.Length)];
            case 2: // flip several bytes
                for (var i = 0; i < 8; i++)
                {
                    mutated[rng.Next(mutated.Length)] ^= (byte)(1 + rng.Next(255));
                }

                return mutated;
            default: // duplicate a random chunk into a random position
                var start = rng.Next(mutated.Length);
                var length = Math.Min(rng.Next(1, 64), mutated.Length - start);
                var insertAt = rng.Next(mutated.Length);
                return [.. mutated[..insertAt], .. mutated[start..(start + length)], .. mutated[insertAt..]];
        }
    }

    private static IEnumerable<byte[]> Sources()
    {
        using var builder = new MdocTestBuilder();
        yield return builder.Build();
        yield return Iso18013AnnexDVectors.DeviceResponse;
    }

    [Fact]
    public void Parse_OnMutatedInput_FailsOnlyWithTypedErrors()
    {
        var rng = new Random(Seed);
        foreach (var source in Sources())
        {
            for (var i = 0; i < Iterations; i++)
            {
                var mutated = Mutate(source, rng);
                try
                {
                    var response = DeviceResponseParser.Parse(Base64UrlEncoder.Encode(mutated));
                    foreach (var document in response.Documents)
                    {
                        try
                        {
                            DeviceResponseParser.ParseMso(document.IssuerAuth);
                        }
                        catch (MdocProcessingException)
                        {
                        }
                    }
                }
                catch (MdocProcessingException)
                {
                }
#pragma warning disable CA1031 // the assertion is exactly that no other exception type escapes
                catch (Exception e)
#pragma warning restore CA1031
                {
                    Assert.Fail($"Unexpected {e.GetType().Name} at seed {Seed} iteration {i}: {e.Message}");
                }
            }
        }
    }

    [Fact]
    public async Task VerifyAsync_OnMutatedInput_NeverThrows()
    {
        using var builder = new MdocTestBuilder();
        var verifier = new MdocVerifier(new StaticTrustListResolver(
            [builder.DsCertificate.Subject], source: "fuzz", trustAnchors: [builder.IacaCertificate]));
        var context = new MdocVerificationContext
        {
            ExpectedDocType = MdocTestBuilder.DefaultDocType,
            ClientId = builder.ClientId,
            Nonce = builder.Nonce,
            ResponseUri = builder.ResponseUri,
        };

        var rng = new Random(Seed);
        var source = builder.Build();
        for (var i = 0; i < Iterations; i++)
        {
            var mutated = Mutate(source, rng);
            try
            {
                // The verifier's contract: a result, valid or invalid — never an exception.
                _ = await verifier.VerifyAsync(new PresentedCredential
                {
                    Format = MdocVerifier.Format,
                    RawValue = Base64UrlEncoder.Encode(mutated),
                }, context);
            }
#pragma warning disable CA1031
            catch (Exception e)
#pragma warning restore CA1031
            {
                Assert.Fail($"VerifyAsync threw {e.GetType().Name} at seed {Seed} iteration {i}: {e.Message}");
            }
        }
    }
}
