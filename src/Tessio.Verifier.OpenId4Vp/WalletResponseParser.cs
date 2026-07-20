using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// Parses wallet authorization responses — <c>direct_post</c> (cleartext form) and
/// <c>direct_post.jwt</c> (encrypted JWE in the <c>response</c> form parameter) — and extracts the
/// presented credentials from <c>vp_token</c>.
/// </summary>
// SPEC: OpenID4VP 1.0 §8.2 (direct_post) and §8.3 (direct_post.jwt).
public sealed class WalletResponseParser : IPresentationResponseParser
{
    private readonly WalletResponseParserOptions _options;

    /// <summary>Creates the parser.</summary>
    public WalletResponseParser(WalletResponseParserOptions? options = null) =>
        _options = options ?? new WalletResponseParserOptions();

    /// <inheritdoc />
    public async Task<IReadOnlyList<PresentedCredential>> ParseAsync(
        WalletResponseData response, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(response);

        // SPEC: OpenID4VP 1.0 §8.2 — the wallet POSTs application/x-www-form-urlencoded.
        if (!response.ContentType.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            throw new WalletResponseException(
                $"Unsupported wallet response content type '{response.ContentType}'; expected application/x-www-form-urlencoded.");
        }

        string vpTokenJson;
        if (response.Form.TryGetValue("response", out var jwtValues))
        {
            // direct_post.jwt: the whole authorization response rides inside one (encrypted) JWT.
            vpTokenJson = await ExtractVpTokenFromResponseJwtAsync(SingleValue(jwtValues, "response")).ConfigureAwait(false);
        }
        else if (response.Form.TryGetValue("vp_token", out var vpValues))
        {
            vpTokenJson = SingleValue(vpValues, "vp_token");
        }
        else
        {
            throw new WalletResponseException("The wallet response carries neither 'vp_token' nor 'response'.");
        }

        return ExtractCredentials(vpTokenJson);
    }

    private static string SingleValue(IReadOnlyList<string> values, string name) =>
        values.Count == 1
            ? values[0]
            : throw new WalletResponseException($"The '{name}' form parameter must appear exactly once (found {values.Count}).");

    private async Task<string> ExtractVpTokenFromResponseJwtAsync(string responseJwt)
    {
        if (_options.ResponseDecryptionKey is null)
        {
            throw new WalletResponseException(
                "Received a direct_post.jwt response but no ResponseDecryptionKey is configured.");
        }

        // SPEC: OpenID4VP 1.0 §8.3 — the response JWT is encrypted to the verifier's client_metadata
        // key (JARM). HAIP profiles it as encrypted-only, so no wallet signature is required here.
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(responseJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = false,
            TokenDecryptionKey = _options.ResponseDecryptionKey,
        }).ConfigureAwait(false);

        if (!result.IsValid)
        {
            throw new WalletResponseException(
                "The direct_post.jwt response could not be decrypted with the configured key.",
                result.Exception);
        }

        if (!result.Claims.TryGetValue("vp_token", out var vpToken))
        {
            throw new WalletResponseException("The decrypted wallet response carries no vp_token claim.");
        }

        return vpToken as string ?? JsonSerializer.Serialize(vpToken);
    }

    private List<PresentedCredential> ExtractCredentials(string vpTokenJson)
    {
        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(vpTokenJson);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            // A bare compact serialization (not JSON) is a single presentation string.
            return [MakeCredential(vpTokenJson)];
        }

        // SPEC: OpenID4VP 1.0 §8.1 — vp_token is a JSON object mapping each DCQL Credential Query id
        // to an array of one or more presentations. Strings and single values are handled leniently
        // for pre-final wallets.
        var credentials = new List<PresentedCredential>();
        switch (root.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var query in root.EnumerateObject())
                {
                    CollectPresentations(query.Value, credentials);
                }

                break;
            case JsonValueKind.Array or JsonValueKind.String:
                CollectPresentations(root, credentials);
                break;
            default:
                throw new WalletResponseException("vp_token is neither a JSON object, an array, nor a string.");
        }

        if (credentials.Count == 0)
        {
            throw new WalletResponseException("vp_token contains no presentations.");
        }

        return credentials;
    }

    private void CollectPresentations(JsonElement element, List<PresentedCredential> credentials)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                credentials.Add(MakeCredential(element.GetString()!));
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    CollectPresentations(item, credentials);
                }

                break;
            default:
                throw new WalletResponseException($"Unsupported presentation value of kind {element.ValueKind} in vp_token.");
        }
    }

    private PresentedCredential MakeCredential(string presentation) => new()
    {
        Format = _options.PresentationFormat,
        RawValue = presentation,
    };
}
