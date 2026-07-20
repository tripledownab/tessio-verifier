namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Plausible sample values for well-known PID-style claims, shared by the DEMO result factory and
/// the MOCK credential issuer so both modes present the same test persona.
/// </summary>
internal static class SampleClaimValues
{
    private static readonly Dictionary<string, object> Values = new(StringComparer.Ordinal)
    {
        ["age_over_18"] = true,
        ["age_over_21"] = true,
        ["given_name"] = "Erika",
        ["family_name"] = "Mustermann",
        ["birthdate"] = "1984-01-26",
        ["nationality"] = "DE",
        ["issuing_country"] = "DE",
        ["resident_country"] = "DE",
        ["email"] = "erika.mustermann@example.com",
    };

    public static object For(string claimName) =>
        Values.TryGetValue(claimName, out var value) ? value : "demo-value";
}
