using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// What marks a request as minted for the same-device flow, and how the callback recognises one.
/// </summary>
/// <remarks>
/// <para>
/// The mark is the request's own <c>response_uri</c>, kept beside the store's binding as a second witness. No
/// session that either one calls same-device completes unbound: the binding holds its presentation, and the
/// mark alone has it refused, so a store that loses one of the two still fails closed. The same-device route refuses to hand out a request that does not carry the mark, which a
/// custom <see cref="IPresentationRequestBuilder"/> that ignores the response URI it is given would produce.
/// </para>
/// <para>
/// The callback reads the mark from the stored request, never from the path the post arrived on: a post to
/// the plain callback path for a bound session would otherwise skip the hold.
/// </para>
/// </remarks>
internal static class SameDeviceRequests
{
    /// <summary>The callback path under the route prefix for a same-device request.</summary>
    public const string CallbackPath = "/callback/same-device";

    /// <summary>Whether <paramref name="request"/> was minted for the same-device flow.</summary>
    /// <remarks>
    /// Case insensitive and blind to a trailing slash, as routing is, so a request whose wallet would reach the
    /// same-device callback is never read as cross-device.
    /// </remarks>
    public static bool IsSameDevice(PresentationRequest request) =>
        RequestParameters.TryGetResponseUri(request) is { } responseUri
        && Uri.TryCreate(responseUri, UriKind.Absolute, out var uri)
        && uri.AbsolutePath.TrimEnd('/').EndsWith(CallbackPath, StringComparison.OrdinalIgnoreCase);
}
