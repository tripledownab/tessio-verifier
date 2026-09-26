using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// The JSON settings every protocol payload in this library is written with. One instance, shared by
/// both assemblies: the DCQL query, client_metadata, the request object and the demo request builder
/// all serialize the same way or they drift, and a payload that escapes differently from the one the
/// conformance suite checked is a defect nobody sees until a wallet rejects it.
/// </summary>
internal static class JsonDefaults
{
    /// <summary>
    /// Relaxed escaping, so a protocol payload keeps characters such as <c>+</c> literal (for example
    /// <c>dc+sd-jwt</c>) rather than emitting <c>+</c>. These are JWT and JSON payloads, not HTML,
    /// so HTML escaping only hurts readability and interop.
    /// </summary>
    /// <remarks>
    /// The resolver is not decoration. Any custom <see cref="JsonSerializerOptions"/> without one
    /// throws "JsonSerializerOptions instance must specify a TypeInfoResolver setting before being
    /// marked as read-only" on net8.0 the moment a <see cref="System.Text.Json.Nodes.JsonValue"/> built
    /// by a GENERIC api is serialized under it, which is what <c>JsonArray.Add&lt;T&gt;</c> produces.
    /// net10.0 does not throw, so the failure reaches only one of the two target frameworks and only at
    /// run time. Setting it here means no caller has to know, and none of them did: the same trap cost
    /// this library twice, in <c>DemoRequestOptionsFactory</c> and again in <c>Dcql</c>.
    /// </remarks>
    public static readonly JsonSerializerOptions Relaxed = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
    };
}
