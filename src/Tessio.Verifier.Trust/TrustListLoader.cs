using System.Text.Json;

namespace Tessio.Verifier.Trust;

/// <summary>
/// Loads a <see cref="StaticTrustListResolver"/> from a JSON trust-list document of the form
/// <c>{"trusted_issuers": ["https://issuer.example", …]}</c>, read from a local file or an HTTPS URL.
/// </summary>
public static class TrustListLoader
{
    /// <summary>Loads a trust list from a local file path or an HTTPS URL.</summary>
    /// <param name="pathOrUrl">A file path, or an absolute https:// URL.</param>
    /// <param name="httpClient">HTTP client used for URL sources; required for URLs.</param>
    /// <param name="ct">Cancellation token.</param>
    public static async Task<StaticTrustListResolver> LoadAsync(
        string pathOrUrl, HttpClient? httpClient = null, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pathOrUrl);

        if (Uri.TryCreate(pathOrUrl, UriKind.Absolute, out var url) && url.Scheme == Uri.UriSchemeHttps)
        {
            ArgumentNullException.ThrowIfNull(httpClient);
            await using var stream = await httpClient.GetStreamAsync(url, ct).ConfigureAwait(false);
            return await FromJsonAsync(stream, pathOrUrl, ct).ConfigureAwait(false);
        }

        await using var file = File.OpenRead(pathOrUrl);
        return await FromJsonAsync(file, pathOrUrl, ct).ConfigureAwait(false);
    }

    /// <summary>Parses a trust-list JSON document from a stream.</summary>
    public static async Task<StaticTrustListResolver> FromJsonAsync(
        Stream json, string source = "json", CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(json);

        using var document = await JsonDocument.ParseAsync(json, cancellationToken: ct).ConfigureAwait(false);
        if (!document.RootElement.TryGetProperty("trusted_issuers", out var issuers)
            || issuers.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("The trust list document carries no 'trusted_issuers' array.");
        }

        var list = issuers.EnumerateArray()
            .Where(static e => e.ValueKind == JsonValueKind.String)
            .Select(static e => e.GetString()!)
            .ToList();

        return new StaticTrustListResolver(list, source);
    }
}
