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
        WalletResponseData response, CancellationToken ct = default) =>
        (await ParseDetailedAsync(response, ct).ConfigureAwait(false)).Credentials;

    /// <summary>
    /// Parses the response including the <c>state</c> needed for session correlation. Prefer this
    /// over <see cref="ParseAsync"/> when hosting the wallet callback: for <c>direct_post.jwt</c>
    /// the state travels inside the encrypted JWT.
    /// </summary>
    /// <exception cref="WalletResponseException">
    /// The response is malformed in any part its sender controls, or cannot be decrypted with the configured
    /// key. A caller that answers this exception as an invalid response has answered every such response.
    /// </exception>
    public async Task<ParsedWalletResponse> ParseDetailedAsync(
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
        string? state;
        var encrypted = false;
        if (response.Form.TryGetValue("response", out var jwtValues))
        {
            // direct_post.jwt: the whole authorization response rides inside one (encrypted) JWT.
            (vpTokenJson, state) = await UnwrapResponseJwtAsync(SingleValue(jwtValues, "response")).ConfigureAwait(false);
            encrypted = true;
        }
        else if (response.Form.TryGetValue("vp_token", out var vpValues))
        {
            vpTokenJson = SingleValue(vpValues, "vp_token");
            state = response.Form.TryGetValue("state", out var stateValues)
                ? SingleValue(stateValues, "state")
                : null;
        }
        else
        {
            throw new WalletResponseException("The wallet response carries neither 'vp_token' nor 'response'.");
        }

        return new ParsedWalletResponse
        {
            Credentials = ExtractCredentials(vpTokenJson),
            State = state,
            Encrypted = encrypted,
        };
    }

    private static string SingleValue(IReadOnlyList<string> values, string name) =>
        values.Count == 1
            ? values[0]
            : throw new WalletResponseException($"The '{name}' form parameter must appear exactly once (found {values.Count}).");

    private async Task<(string VpTokenJson, string? State)> UnwrapResponseJwtAsync(string responseJwt)
    {
        // Through CompactJwt, which is where this library states what a malformed token looks like.
        // Written inline this named one of the constructor's two complaints and let the other escape the
        // parser, so a caller that had correctly wrapped this in a WalletResponseException handler could
        // still meet an exception it had no reason to expect.
        if (!CompactJwt.TryParse(responseJwt, out var jwe))
        {
            throw new WalletResponseException("The direct_post.jwt response is not a well-formed JWT/JWE.");
        }

        // SPEC: OpenID4VP 1.0 §8.3: "To encrypt the Authorization Response, implementations MUST use an
        // unsigned, encrypted JWT". A response parameter that is not a JWE is therefore not a
        // direct_post.jwt response. It is refused here, before the handler below, which does not require
        // a signature.
        if (!jwe.IsEncrypted)
        {
            throw new WalletResponseException(
                "The direct_post.jwt response is not encrypted. OpenID4VP 1.0 §8.3 requires an unsigned, encrypted JWT (a JWE).");
        }

        // Before any key is looked up: these rules hold whatever the key, and a response that breaks them
        // should not cost a key store lookup.
        JweHeaderRules.Enforce(jwe);

        // Keys are ephemeral per authorization request, so the resolver picks the session's key by the
        // kid the wallet echoes from our client_metadata. The fixed key remains for single-key callers.
        var decryptionKey = _options.ResponseDecryptionKeyResolver is { } resolve
            ? resolve(jwe.Kid is { Length: > 0 } kid ? kid : null)
            : _options.ResponseDecryptionKey;

        if (decryptionKey is null)
        {
            throw new WalletResponseException(_options.ResponseDecryptionKeyResolver is null
                ? "Received a direct_post.jwt response but no ResponseDecryptionKey is configured."
                : "The direct_post.jwt response names no known response-encryption key: its kid matches "
                  + "no live session, so the session may have expired or the response may be a replay.");
        }

        // SPEC: OpenID4VP 1.0 §8.3 — the response JWT is encrypted to the verifier's client_metadata
        // key (JARM). HAIP profiles it as encrypted-only, so no wallet signature is required here.
        // ECDH-ES (what HAIP wallets send) needs our own receive side; IdentityModel only ships the
        // sender half. Everything else (dir, RSA-OAEP, …) goes through the library handler.
        if (EcdhEsJweDecryptor.CanHandle(jwe))
        {
            var plaintext = EcdhEsJweDecryptor.Decrypt(jwe, decryptionKey);
            return ExtractResponseClaims(NormalizeDecryptedPayload(plaintext));
        }

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(responseJwt, new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireSignedTokens = false,
            TokenDecryptionKey = decryptionKey,
        }).ConfigureAwait(false);

        if (!result.IsValid)
        {
            throw new WalletResponseException(
                "The direct_post.jwt response could not be decrypted with the configured key, or its content is not a readable JWT.",
                result.Exception);
        }

        // Read by the same ExtractResponseClaims as the ECDH-ES route, from the decrypted token's own payload,
        // so the response parameters are read one way whichever key decrypted them. The handler's typed
        // claims would be a second reading of the same JSON, free to disagree with the first.
        if (result.SecurityToken is not JsonWebToken { InnerToken: { } inner })
        {
            throw new WalletResponseException("The direct_post.jwt response decrypted to no token.");
        }

        return ExtractResponseClaims(Base64UrlEncoder.Decode(inner.EncodedPayload));
    }

    /// <summary>
    /// A decrypted response is either the response-parameter JSON directly, or a nested (typically
    /// unsigned — the JWE's AEAD provides integrity) JWT whose payload carries the parameters.
    /// </summary>
    private static string NormalizeDecryptedPayload(string plaintext)
    {
        if (plaintext.TrimStart().StartsWith('{'))
        {
            return plaintext;
        }

        // The plaintext is attacker-reachable despite arriving from a decryption: ECDH-ES is anonymous
        // key agreement, so anyone holding the client_metadata public key can encrypt a payload of their
        // choosing to it. The nested JWT here is therefore untrusted input like any other.
        if (!CompactJwt.TryParse(plaintext, out var nested))
        {
            throw new WalletResponseException("The decrypted wallet response is neither JSON nor a nested JWT.");
        }

        return Base64UrlEncoder.Decode(nested.EncodedPayload);
    }

    private static (string VpTokenJson, string? State) ExtractResponseClaims(string payloadJson)
    {
        // A decrypted payload is untrusted input (see NormalizeDecryptedPayload), so a payload that only
        // looks like JSON is a malformed response, answered like every other, not an exception that
        // escapes the parser.
        JsonDocument parsed;
        try
        {
            parsed = JsonDocument.Parse(payloadJson);
        }
        catch (JsonException e)
        {
            throw new WalletResponseException("The decrypted wallet response is not well formed JSON.", e);
        }

        using var document = parsed;
        // The response parameters are members of an object, and the reads below need one. Every route that
        // reaches here delivers an object today; checked here so these reads do not depend on that.
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new WalletResponseException("The decrypted wallet response is not a JSON object.");
        }

        RequireReadableText(document.RootElement);
        if (!document.RootElement.TryGetProperty("vp_token", out var vpToken))
        {
            throw new WalletResponseException("The decrypted wallet response carries no vp_token claim.");
        }

        var state = document.RootElement.TryGetProperty("state", out var stateProp)
                    && stateProp.ValueKind == JsonValueKind.String
            ? stateProp.GetString()
            : null;

        var vpTokenJson = vpToken.ValueKind == JsonValueKind.String ? vpToken.GetString()! : vpToken.GetRawText();
        return (vpTokenJson, state);
    }

    private List<PresentedCredential> ExtractCredentials(string vpTokenJson)
    {
        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(vpTokenJson);
            RequireReadableText(document.RootElement);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            // A bare compact serialization (not JSON) is a single presentation string.
            return [MakeCredential(vpTokenJson)];
        }
        catch (ArgumentException e)
        {
            // A string that is not valid UTF-16, which a host's own form reading can hand over.
            throw new WalletResponseException("The vp_token in the wallet response is not valid text.", e);
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

    /// <summary>
    /// Refuses a parsed response holding a name or string that is not text. Well formed JSON can carry an
    /// escaped lone UTF-16 surrogate: it parses, and only the read that unescapes it fails, whichever read
    /// that is. Reading every name and string once, here, straight after parsing, makes that a malformed
    /// response, and leaves no later read of the document able to fail on it.
    /// </summary>
    // Recursion is bounded: JsonDocument refuses nesting past its maximum depth when parsing.
    private static void RequireReadableText(JsonElement element)
    {
        try
        {
            ReadAllText(element);
        }
        catch (InvalidOperationException e)
        {
            throw new WalletResponseException("The wallet response holds a name or string that is not valid text.", e);
        }

        static void ReadAllText(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        _ = property.Name;
                        ReadAllText(property.Value);
                    }

                    break;
                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        ReadAllText(item);
                    }

                    break;
                case JsonValueKind.String:
                    _ = element.GetString();
                    break;
            }
        }
    }

    private PresentedCredential MakeCredential(string presentation) => new()
    {
        Format = _options.PresentationFormat,
        RawValue = presentation,
    };
}
