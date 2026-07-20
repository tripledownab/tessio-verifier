using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Tokens;

namespace Tessio.Verifier.Core;

/// <summary>
/// Reconstructs the disclosed payload of an SD-JWT per RFC 9901 §7.1: resolves <c>_sd</c> digest
/// arrays and <c>{"...": digest}</c> array elements (recursively), enforcing every MUST-reject rule —
/// duplicate digests, unreferenced disclosures, reserved claim names, and duplicate claim names.
/// </summary>
internal static class DisclosureProcessor
{
    /// <summary>
    /// Computes the digest of a disclosure: base64url(SHA-256(US-ASCII(disclosure))).
    /// </summary>
    // SPEC: RFC 9901 §4.2.3 — the hash input is the base64url-encoded disclosure string itself,
    // NOT the bytes it decodes to. Known-answer vector: disclosure
    // "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
    // → digest "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0".
    public static string ComputeDigest(string disclosure) =>
        Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(disclosure)));

    /// <summary>
    /// Processes the issuer-signed payload against the presented disclosures. Returns the
    /// reconstructed payload (digests replaced by disclosed claims, undisclosed digests removed).
    /// Throws <see cref="SdJwtProcessingException"/> on any MUST-reject violation.
    /// </summary>
    public static JsonObject Process(JsonObject payload, IReadOnlyList<string> disclosures)
    {
        ValidateSdAlg(payload);

        var byDigest = IndexDisclosures(disclosures);
        var state = new ProcessingState(byDigest);

        ProcessObject(payload, state, isTopLevel: true);

        // SPEC: RFC 9901 §7.1 step 5 — every presented disclosure must be referenced by a digest
        // (directly or recursively); otherwise the SD-JWT MUST be rejected.
        var unreferenced = byDigest.Keys.Except(state.ConsumedDigests, StringComparer.Ordinal).ToList();
        if (unreferenced.Count > 0)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.DisclosureUnreferenced,
                $"{unreferenced.Count} disclosure(s) are not referenced by any digest in the credential.");
        }

        payload.Remove(SdJwtConstants.SdAlgClaim);
        return payload;
    }

    private static void ValidateSdAlg(JsonObject payload)
    {
        // SPEC: RFC 9901 §4.1.1 — _sd_alg appears only at top level; default is "sha-256";
        // implementations MUST support sha-256. Unknown algorithms make digests unverifiable → reject.
        if (payload.TryGetPropertyValue(SdJwtConstants.SdAlgClaim, out var algNode))
        {
            var alg = algNode?.GetValueKind() == JsonValueKind.String ? algNode.GetValue<string>() : null;
            if (!string.Equals(alg, SdJwtConstants.DefaultSdAlg, StringComparison.Ordinal))
            {
                throw new SdJwtProcessingException(
                    ErrorCodes.SdAlgUnsupported,
                    $"Unsupported _sd_alg '{alg ?? "<non-string>"}'; this verifier supports 'sha-256'.");
            }
        }
    }

    private static Dictionary<string, JsonArray> IndexDisclosures(IReadOnlyList<string> disclosures)
    {
        var byDigest = new Dictionary<string, JsonArray>(disclosures.Count, StringComparer.Ordinal);
        foreach (var disclosure in disclosures)
        {
            var digest = ComputeDigest(disclosure);
            if (!byDigest.TryAdd(digest, DecodeDisclosure(disclosure)))
            {
                // Two identical disclosures presented — their shared digest cannot appear twice.
                throw new SdJwtProcessingException(
                    ErrorCodes.DigestDuplicated, "The same disclosure was presented more than once.");
            }
        }

        return byDigest;
    }

    private static JsonArray DecodeDisclosure(string disclosure)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(Base64UrlEncoder.Decode(disclosure));
        }
        catch (Exception e) when (e is JsonException or FormatException)
        {
            throw new SdJwtProcessingException(
                ErrorCodes.DisclosureInvalid, "A disclosure is not base64url-encoded JSON.");
        }

        // SPEC: RFC 9901 §4.2.1/§4.2.2 — [salt, name, value] for object properties,
        // [salt, value] for array elements. Salt (and name) must be strings.
        if (node is not JsonArray array
            || array.Count is not (2 or 3)
            || array[0]?.GetValueKind() != JsonValueKind.String
            || (array.Count == 3 && array[1]?.GetValueKind() != JsonValueKind.String))
        {
            throw new SdJwtProcessingException(
                ErrorCodes.DisclosureInvalid,
                "A disclosure is not a [salt, name, value] or [salt, value] JSON array.");
        }

        return array;
    }

    private static void ProcessNode(JsonNode? node, ProcessingState state)
    {
        switch (node)
        {
            case JsonObject obj:
                ProcessObject(obj, state, isTopLevel: false);
                break;
            case JsonArray array:
                ProcessArray(array, state);
                break;
            default:
                break; // Scalars need no processing.
        }
    }

    private static void ProcessObject(JsonObject obj, ProcessingState state, bool isTopLevel)
    {
        // SPEC: RFC 9901 §7.1 step 3.2 — resolve the _sd array at this level, then recurse.
        if (obj.TryGetPropertyValue(SdJwtConstants.SdClaim, out var sdNode))
        {
            if (sdNode is not JsonArray sdArray)
            {
                throw new SdJwtProcessingException(
                    ErrorCodes.StructureInvalid, "The _sd claim is not an array of digests.");
            }

            obj.Remove(SdJwtConstants.SdClaim);

            foreach (var digestNode in sdArray)
            {
                if (digestNode?.GetValueKind() != JsonValueKind.String)
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.StructureInvalid, "An _sd entry is not a string digest.");
                }

                var digest = digestNode.GetValue<string>();
                state.RegisterDigest(digest);

                if (!state.Disclosures.TryGetValue(digest, out var disclosure))
                {
                    continue; // Undisclosed claim or decoy digest — ignore (RFC 9901 §4.2.5).
                }

                if (disclosure.Count != 3)
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.DisclosureInvalid,
                        "An array-element disclosure was referenced from an _sd (object) digest.");
                }

                var name = disclosure[1]!.GetValue<string>();

                // SPEC: RFC 9901 §7.1 step 3.2.2 — inserted claim name must not be "_sd" or "...".
                if (name is SdJwtConstants.SdClaim or SdJwtConstants.ArrayDigestKey)
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.ClaimNameReserved, $"A disclosure uses the reserved claim name '{name}'.");
                }

                // SPEC: draft-ietf-oauth-sd-jwt-vc §2.2.2.2 — registered credential claims
                // (iss, nbf, exp, cnf, vct, vct#integrity, status) must never arrive via disclosure.
                if (isTopLevel && SdJwtConstants.NeverSelectivelyDisclosable.Contains(name))
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.ClaimNotDisclosable,
                        $"The claim '{name}' must not be selectively disclosable in an SD-JWT VC.");
                }

                // SPEC: RFC 9901 §7.1 step 3.2.2.3 — duplicate claim name at this level → reject.
                var value = disclosure[2].CloneForInsert();
                if (!obj.TryAdd(name, value))
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.ClaimNameDuplicated,
                        $"The disclosed claim '{name}' already exists in the credential.");
                }

                state.MarkConsumed(digest);
                ProcessNode(value, state); // Recursive disclosures (RFC 9901 §4.2.6).
            }
        }

        foreach (var property in obj.ToList())
        {
            ProcessNode(property.Value, state);
        }
    }

    private static void ProcessArray(JsonArray array, ProcessingState state)
    {
        // SPEC: RFC 9901 §4.2.4.2 / §7.1 steps 3.2.3–3.2.4 — an element of exactly {"...": digest}
        // is replaced by its disclosed value, or removed when undisclosed.
        for (var i = array.Count - 1; i >= 0; i--)
        {
            if (array[i] is JsonObject candidate
                && candidate.Count == 1
                && candidate.TryGetPropertyValue(SdJwtConstants.ArrayDigestKey, out var digestNode))
            {
                if (digestNode?.GetValueKind() != JsonValueKind.String)
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.StructureInvalid, "A '...' array-element value is not a string digest.");
                }

                var digest = digestNode.GetValue<string>();
                state.RegisterDigest(digest);

                if (!state.Disclosures.TryGetValue(digest, out var disclosure))
                {
                    array.RemoveAt(i); // Undisclosed element — remove.
                    continue;
                }

                if (disclosure.Count != 2)
                {
                    throw new SdJwtProcessingException(
                        ErrorCodes.DisclosureInvalid,
                        "An object-property disclosure was referenced from a '...' (array) digest.");
                }

                var value = disclosure[1].CloneForInsert();
                array[i] = value;
                state.MarkConsumed(digest);
                ProcessNode(value, state);
            }
            else
            {
                ProcessNode(array[i], state);
            }
        }
    }

    private static JsonNode? CloneForInsert(this JsonNode? node) => node?.DeepClone();

    private sealed class ProcessingState
    {
        private readonly HashSet<string> _seenDigests = new(StringComparer.Ordinal);
        private readonly HashSet<string> _consumedDigests = new(StringComparer.Ordinal);

        public ProcessingState(Dictionary<string, JsonArray> disclosures) => Disclosures = disclosures;

        public Dictionary<string, JsonArray> Disclosures { get; }

        public IReadOnlySet<string> ConsumedDigests => _consumedDigests;

        // SPEC: RFC 9901 §4.1 — the same digest value MUST NOT appear more than once in the SD-JWT.
        public void RegisterDigest(string digest)
        {
            if (!_seenDigests.Add(digest))
            {
                throw new SdJwtProcessingException(
                    ErrorCodes.DigestDuplicated, "A digest value appears more than once in the credential.");
            }
        }

        public void MarkConsumed(string digest) => _consumedDigests.Add(digest);
    }
}
