namespace Tessio.Verifier.Core;

/// <summary>
/// The parsed parts of an SD-JWT presentation in compact serialization:
/// <c>&lt;Issuer-signed JWT&gt;~&lt;Disclosure 1&gt;~…~&lt;Disclosure N&gt;~[&lt;KB-JWT&gt;]</c>.
/// </summary>
// SPEC: RFC 9901 §4 — without a KB-JWT the presentation MUST end with '~' (empty last element);
// with Key Binding the KB-JWT follows the final '~'.
internal sealed record SdJwtPresentation
{
    public required string IssuerJwt { get; init; }

    public required IReadOnlyList<string> Disclosures { get; init; }

    public required string? KbJwt { get; init; }

    /// <summary>
    /// Everything up to and including the final <c>~</c> — the exact input to the KB-JWT
    /// <c>sd_hash</c> computation (RFC 9901 §4.3.1).
    /// </summary>
    public required string PresentationWithoutKbJwt { get; init; }

    public static bool TryParse(string raw, out SdJwtPresentation presentation)
    {
        presentation = null!;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var parts = raw.Split(SdJwtConstants.Separator);
        if (parts.Length < 2)
        {
            return false; // A presentation must contain at least "<jwt>~".
        }

        var issuerJwt = parts[0];
        var kbJwt = parts[^1].Length > 0 ? parts[^1] : null;
        var disclosures = parts[1..^1];

        // The issuer JWT and every disclosure must be non-empty; "a~~b" is malformed.
        if (issuerJwt.Length == 0 || disclosures.Any(static d => d.Length == 0))
        {
            return false;
        }

        var withoutKb = raw[..(raw.LastIndexOf(SdJwtConstants.Separator) + 1)];

        presentation = new SdJwtPresentation
        {
            IssuerJwt = issuerJwt,
            Disclosures = disclosures,
            KbJwt = kbJwt,
            PresentationWithoutKbJwt = withoutKb,
        };
        return true;
    }
}
