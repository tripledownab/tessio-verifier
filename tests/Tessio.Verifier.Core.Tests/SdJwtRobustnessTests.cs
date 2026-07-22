namespace Tessio.Verifier.Core.Tests;

/// <summary>
/// Mutation-based robustness for the SD-JWT pipeline, mirroring the mdoc fuzz suite: presentations
/// are attacker-controlled strings, so <see cref="SdJwtVcVerifier"/> must return a
/// result (valid or invalid) on every mutated input and never throw. Covers both key-resolution
/// paths (issuer metadata and x5c). Seeded for determinism; failures print seed and iteration.
/// </summary>
public class SdJwtRobustnessTests
{
    private const int Iterations = 400;
    private const int Seed = 20260722;

    // The presentation alphabet plus deliberately hostile characters (quote, backslash, NUL).
    private static readonly char[] MutationChars =
        [.. "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~=+/{}[] ", '"', (char)92, (char)0, (char)233];

    private static string Mutate(string source, Random rng)
    {
        var chars = source.ToCharArray();
        switch (rng.Next(4))
        {
            case 0: // replace one char
                chars[rng.Next(chars.Length)] = MutationChars[rng.Next(MutationChars.Length)];
                return new string(chars);
            case 1: // truncate
                return source[..rng.Next(source.Length)];
            case 2: // replace several chars
                for (var i = 0; i < 12; i++)
                {
                    chars[rng.Next(chars.Length)] = MutationChars[rng.Next(MutationChars.Length)];
                }

                return new string(chars);
            default: // duplicate a random chunk into a random position
                var start = rng.Next(source.Length);
                var length = Math.Min(rng.Next(1, 48), source.Length - start);
                var insertAt = rng.Next(source.Length);
                return string.Concat(source.AsSpan(..insertAt), source.AsSpan(start, length), source.AsSpan(insertAt));
        }
    }

    private static VerificationContext Context() => new()
    {
        Nonce = TestCredentialBuilder.DefaultNonce,
        Audience = TestCredentialBuilder.DefaultAudience,
    };

    [Fact]
    public async Task VerifyAsync_MetadataResolution_OnMutatedInput_NeverThrows()
    {
        var builder = new TestCredentialBuilder();
        var http = new FakeHttpHandler().Map(
            "https://issuer.example/.well-known/jwt-vc-issuer",
            $$"""{"issuer":"{{builder.Issuer}}","jwks":{{builder.BuildJwksJson()}}}""");
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(http));

        await RunAsync(verifier, builder.Build());
    }

    [Fact]
    public async Task VerifyAsync_X5cResolution_OnMutatedInput_NeverThrows()
    {
        var builder = new TestCredentialBuilder();
        using var certificate = builder.UseCertificate();
        var verifier = new SdJwtVcVerifier(new FakeTrustListResolver(), httpClient: new HttpClient(new FakeHttpHandler()));

        await RunAsync(verifier, builder.Build());
    }

    private static async Task RunAsync(SdJwtVcVerifier verifier, string presentation)
    {
        var rng = new Random(Seed);
        for (var i = 0; i < Iterations; i++)
        {
            var mutated = Mutate(presentation, rng);
            try
            {
                _ = await verifier.VerifyAsync(
                    new PresentedCredential { Format = "dc+sd-jwt", RawValue = mutated },
                    Context(),
                    CancellationToken.None);
            }
#pragma warning disable CA1031 // the assertion is exactly that nothing escapes
            catch (Exception e)
#pragma warning restore CA1031
            {
                Assert.Fail($"VerifyAsync threw {e.GetType().Name} at seed {Seed} iteration {i}: {e.Message}");
            }
        }
    }
}
