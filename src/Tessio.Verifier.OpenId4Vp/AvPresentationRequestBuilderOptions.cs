namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Construction-time options for <see cref="AvPresentationRequestBuilder"/>.
/// </summary>
/// <remarks>
/// Separate from <see cref="PresentationRequestBuilderOptions"/>, which requires
/// <c>SigningCredentials</c>. This profile has no signing key by design, so reusing that type would mean
/// either a fake credential or relaxing a requirement that correctly guards the JAR path.
/// </remarks>
public sealed class AvPresentationRequestBuilderOptions
{
    /// <summary>
    /// Scheme and optional path the request parameters are appended to, as
    /// <c>{AuthorizationEndpoint}?{parameters}</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Defaults to <c>av://</c>, producing <c>av://?response_type=...</c>.
    /// </para>
    /// <para>
    /// <b>This default is a choice between two shapes the specification uses, not something it states.</b>
    /// Annex A requires only that "at least a custom URL scheme av:// MUST be supported", and prints no
    /// worked authorization deeplink: its authorization example is in abstract HTTP form as
    /// <c>GET /authorize?...</c>. Elsewhere it uses <c>av://</c> both ways, pathless for credential offers
    /// (<c>av://?credential_offer=...</c>) and with a path for an issuance redirect
    /// (<c>Location: av://callback?code=...</c>). Pathless is chosen because it is the form used for a
    /// request the app receives rather than a redirect it registered.
    /// </para>
    /// <para>
    /// <b>Unconfirmed against the app.</b> If it rejects the deeplink, set this to <c>av://authorize</c>
    /// before suspecting anything else in the request.
    /// </para>
    /// </remarks>
    public string AuthorizationEndpoint { get; set; } = "av://";

    /// <summary>Lifetime applied when a request does not specify one.</summary>
    public TimeSpan DefaultRequestLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Clock, for tests. Defaults to <see cref="TimeProvider.System"/>.</summary>
    public TimeProvider? Clock { get; set; }
}
