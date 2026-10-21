using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

// A stand-in that lets a test run Live mode on the demo request builder, which Live mode refuses by type.
// The browser test host compiles this file too.

/// <summary>Builds what the demo builder builds, without being it.</summary>
internal sealed class NotTheDemoBuilder(IPresentationRequestBuilder inner) : IPresentationRequestBuilder
{
    public Task<PresentationRequest> BuildAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
        inner.BuildAsync(options, ct);
}
