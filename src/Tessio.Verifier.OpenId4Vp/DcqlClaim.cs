// What belongs in this file: one entry in a DCQL Claims Query. Where the claim lives, what a claim set
// calls it, and whether the verifier intends to retain it. Nothing about the query around it, which is
// Dcql's job.

namespace Tessio.Verifier.OpenId4Vp;

/// <summary>
/// One claim in a DCQL Claims Query, addressed by path.
/// </summary>
/// <remarks>
/// <para>
/// A PATH rather than a name, because a claim is not always at the top level, and the three shapes in
/// use are not variations of one another. An SD-JWT VC claim usually is top level, so its path has one
/// segment. An mdoc claim never is: OpenID4VP 1.0 §7.2 gives it the two-element path
/// <c>[namespace, element]</c>, and §7.2.1 makes a wallet abort on anything else. A credential type may also nest its own claims, which a national PID
/// does when it carries its age thresholds as keys inside one object rather than as separate booleans.
/// One shape covers all three, and a builder that took names could only ever express the first.
/// </para>
/// <para>
/// The alternative is a builder per shape, which leaves each caller to restate the path it asks for
/// wherever it reads the answer back. Getting that wrong is unusually expensive to diagnose: a wrong
/// path fails as "the wallet disclosed nothing", which reads as the holder having nothing to offer
/// rather than as a naming mistake on the verifier's side.
/// </para>
/// </remarks>
// SPEC: OpenID4VP 1.0 §6.3, Claims Query. An entry carries `path`, an optional `id` that
// `claim_sets` references, and format-specific parameters. NOT §6.4, which is "Selecting Claims and
// Credentials": B.2.4 settles it by pointing at "a Claims Query as defined in Section 6.3".
public sealed record DcqlClaim
{
    /// <summary>Where the claim lives, one segment per level. Must have at least one segment.</summary>
    /// <remarks>
    /// Every segment is a NAME, and that is narrower than the specification allows. §7.1 permits three
    /// kinds of component in a pointer into a JSON-based credential: a string selects the element under
    /// that KEY, a non-negative integer selects that INDEX in an array, and null selects ALL elements of
    /// an array. A list of strings expresses only the first. The other two have to be hand-written, and
    /// no caller has wanted one.
    /// <para>
    /// The trap that follows, because the two forms look alike: passing <c>"0"</c> does NOT select index
    /// zero. It is a string, so §7.1 has the wallet look for a key named <c>0</c>, and where no such key
    /// exists that element simply drops out of the selection. No error, just a claim that never comes
    /// back.
    /// </para>
    /// </remarks>
    public required IReadOnlyList<string> Path { get; init; }

    /// <summary>
    /// The name a claim set uses to reference this claim.
    /// </summary>
    /// <remarks>
    /// §6.3: "REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise", and the
    /// value "MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-)
    /// characters". The builder checks the character set, uniqueness within the query, and BOTH
    /// directions of the reference: no set may name a claim that is absent, and no claim may sit in no
    /// set, because §6.4.1 requests only the combinations the sets list and an unreferenced claim is
    /// therefore never asked for.
    /// </remarks>
    public string? Id { get; init; }

    /// <summary>
    /// Whether the verifier will retain the claim. mdoc only. Omitted from the query when null.
    /// </summary>
    /// <remarks>
    /// SPEC: OpenID4VP 1.0 section B.2.4 defines <c>intent_to_retain</c> as an mdoc parameter,
    /// "equivalent to IntentToRetain ... of [ISO.18013-5]". It is OPTIONAL, and saying nothing is
    /// conformant, which is exactly why it is worth saying: a request that asks for a date of birth
    /// while staying silent about retention makes the holder guess.
    /// <para>
    /// B.2.4 scopes the parameter to mdoc, so setting it on an SD-JWT VC claim would invent a parameter
    /// the specification does not define there. The builder refuses that rather than emitting it.
    /// </para>
    /// </remarks>
    public bool? IntentToRetain { get; init; }
}
