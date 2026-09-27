using System.Text.Json;

namespace Tessio.Verifier.OpenId4Vp.Tests;

/// <summary>
/// The <see cref="DcqlClaim"/> overloads address a claim by PATH and accept claim sets, which is what
/// a nested claim and a preference order need. The <c>params string[]</c> overloads can express
/// neither.
/// </summary>
/// <remarks>
/// Every assertion here is on the emitted JSON rather than on an intermediate object, because the JSON
/// is what a wallet reads. A builder that constructs the right objects and serialises them wrongly is
/// a bug no object-level test can see.
/// </remarks>
public sealed class DcqlClaimPathTests
{
    private const string GenericPid = "urn:eudi:pid:1";
    private const string GermanPid = "urn:eudi:pid:de:1";
    private const string MdlDocType = "org.iso.18013.5.1.mDL";
    private const string MdlNamespace = "org.iso.18013.5.1";

    private static JsonElement TheOnlyCredential(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var credentials = doc.RootElement.GetProperty("credentials");
        Assert.Equal(1, credentials.GetArrayLength());
        return credentials[0].Clone();
    }

    private static string[] PathOf(JsonElement claim) =>
        [.. claim.GetProperty("path").EnumerateArray().Select(p => p.GetString()!)];

    /// <summary>
    /// Asserts the build is refused AND says which rule refused it.
    /// </summary>
    /// <remarks>
    /// The message, not just the type. EVERY guard in the validator throws ArgumentException, so a
    /// type-only assertion cannot tell which rule ran, and a test written that way keeps passing when its
    /// own guard is deleted and a neighbouring one refuses the same input. Adding a guard can therefore
    /// un-pin an existing test without touching it, which is why these name the rule they expect.
    /// </remarks>
    private static void Refuses(string messageFragment, Action build)
    {
        var ex = Assert.ThrowsAny<ArgumentException>(build);
        Assert.Contains(messageFragment, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SdJwtVc_EmitsANestedPathVerbatim()
    {
        // The shape a national PID uses: age thresholds are keys inside one object, so the answer to
        // "is the holder over 18" lives at age_equal_or_over/18 and not at any top-level claim.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GermanPid],
            [new DcqlClaim { Path = ["age_equal_or_over", "18"] }]));

        var claims = credential.GetProperty("claims");
        Assert.Equal(1, claims.GetArrayLength());
        Assert.Equal(["age_equal_or_over", "18"], PathOf(claims[0]));
    }

    [Fact]
    public void SdJwtVc_AcceptsSeveralTypesAlongsidePathClaims()
    {
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid, GermanPid],
            [new DcqlClaim { Path = ["birthdate"] }]));

        var values = credential.GetProperty("meta").GetProperty("vct_values");
        Assert.Equal([GenericPid, GermanPid], values.EnumerateArray().Select(v => v.GetString()));
    }

    [Fact]
    public void ClaimSets_KeepTheOrderGiven_BecauseOrderIsThePreference()
    {
        // SPEC: OpenID4VP 1.0 section 6.4.1. The wallet SHOULD return the first option it can satisfy,
        // so reordering these two silently changes a request that prefers a boolean into one that
        // prefers a date of birth.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GermanPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_equal_or_over", "18"] },
                new DcqlClaim { Id = "dob", Path = ["birthdate"] },
            ],
            ["age"],
            ["dob"]));

        var sets = credential.GetProperty("claim_sets");
        Assert.Equal(2, sets.GetArrayLength());
        Assert.Equal("age", sets[0][0].GetString());
        Assert.Equal("dob", sets[1][0].GetString());
    }

    [Fact]
    public void EveryClaimSetId_ResolvesToAClaimInTheSameQuery()
    {
        // The ids ARE the link between the two halves, and nothing else in the query expresses it.
        // Emit claim_sets without emitting the matching claim ids and the JSON is still well formed,
        // still passes every other assertion here, and asks a wallet to satisfy combinations it
        // cannot resolve. It answers with no claims, which is indistinguishable from a holder who
        // has nothing. Checked structurally rather than by naming the three ids, so the property
        // holds for whatever a caller passes.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid, GermanPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_over_18"] },
                new DcqlClaim { Id = "agenested", Path = ["age_equal_or_over", "18"] },
                new DcqlClaim { Id = "dob", Path = ["birthdate"] },
            ],
            ["age"],
            ["agenested"],
            ["dob"]));

        var declared = credential.GetProperty("claims").EnumerateArray()
            .Select(c => c.TryGetProperty("id", out var id) ? id.GetString() : null)
            .ToHashSet(StringComparer.Ordinal);

        var referenced = credential.GetProperty("claim_sets").EnumerateArray()
            .SelectMany(set => set.EnumerateArray().Select(id => id.GetString()));

        Assert.All(referenced, id => Assert.Contains(id, declared));
    }

    [Fact]
    public void ClaimSets_AreOmittedEntirely_WhenNoneAreGiven()
    {
        // Not emitted empty. An empty array would say every combination is unacceptable, which is the
        // opposite of "ask for all of them".
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Path = ["birthdate"] }]));

        Assert.False(credential.TryGetProperty("claim_sets", out _));
    }

    [Fact]
    public void Mdoc_CarriesTheFullNamespacedPathAndIntentToRetain()
    {
        // SPEC: §7.2 gives an mdoc claim the two-element path [namespace, element]. B.2.4 defines
        // intent_to_retain for mdoc, and this verifier keeps nothing, so it says so rather than
        // leaving the holder to guess.
        var credential = TheOnlyCredential(Dcql.MdocByPath(
            MdlDocType,
            [new DcqlClaim { Path = [MdlNamespace, "age_over_18"], IntentToRetain = false }]));

        Assert.Equal("mso_mdoc", credential.GetProperty("format").GetString());
        Assert.Equal(MdlDocType, credential.GetProperty("meta").GetProperty("doctype_value").GetString());

        var claim = credential.GetProperty("claims")[0];
        Assert.Equal([MdlNamespace, "age_over_18"], PathOf(claim));
        Assert.False(claim.GetProperty("intent_to_retain").GetBoolean());
    }

    [Fact]
    public void Mdoc_OmitsIntentToRetain_WhenTheCallerSaysNothing()
    {
        var credential = TheOnlyCredential(Dcql.MdocByPath(
            MdlDocType, [new DcqlClaim { Path = [MdlNamespace, "age_over_18"] }]));

        Assert.False(credential.GetProperty("claims")[0].TryGetProperty("intent_to_retain", out _));
    }

    [Fact]
    public void IntentToRetain_IsRefusedOnSdJwtVc_BecauseB24ScopesItToMdoc()
    {
        // Emitting it would invent a parameter the specification does not define for this format, and
        // a wallet is free to reject a request carrying one.
        Refuses("intent_to_retain", () => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Path = ["birthdate"], IntentToRetain = false }]));
    }

    [Fact]
    public void AClaimSetNamingAnAbsentClaim_IsRefusedAtBuildTime()
    {
        // This is the failure worth catching early: the JSON serialises perfectly, and the first sign
        // of trouble is a wallet returning no claims, which reads as the holder having nothing.
        Refuses("no claim in this query carries", () => Dcql.SdJwtVcByPath(
            [GenericPid],
            [new DcqlClaim { Id = "dob", Path = ["birthdate"] }],
            ["age"]));
    }

    [Fact]
    public void AClaimWithoutAnId_IsRefusedWhenTheQueryHasClaimSets()
    {
        // A set references claims by id, so a claim with none can never be selected. Asking for it is
        // therefore always a mistake rather than a way of saying "always include this".
        Refuses("needs an id when the query has claim sets", () => Dcql.SdJwtVcByPath(
            [GenericPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_over_18"] },
                new DcqlClaim { Path = ["birthdate"] },
            ],
            ["age"]));
    }

    [Fact]
    public void TwoClaimsSharingAnId_AreRefused_BecauseASetNamingItIsAmbiguous()
    {
        Refuses("share the id", () => Dcql.SdJwtVcByPath(
            [GenericPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_over_18"] },
                new DcqlClaim { Id = "age", Path = ["age_equal_or_over", "18"] },
            ],
            ["age"]));
    }

    // ThrowsAny, not Throws: null raises ArgumentNullException, which derives from ArgumentException,
    // and Assert.Throws matches the exact type.
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void AnEmptyPathSegment_IsRefused(string? segment)
    {
        Refuses("claims", () => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Path = [segment!] }]));
    }

    [Fact]
    public void AClaimWithNoPathSegments_IsRefused()
    {
        Refuses("at least one path segment", () => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Path = [] }]));
    }

    [Fact]
    public void NoClaims_IsRefusedByThePathBuilders_Because61SaysNonEmpty()
    {
        // SPEC: §6.1 gives `claims` as "OPTIONAL. A non-empty array of objects as defined in [§6.3]".
        // An empty array is not that. These builders are new and have no caller to keep faith with, so
        // they refuse it.
        Refuses("section 6.1", () => Dcql.SdJwtVcByPath([GenericPid], []));
        Refuses("section 6.1", () => Dcql.MdocByPath(MdlDocType, []));
    }

    [Fact]
    public void NoClaims_StillEmitsAnEmptyArray_FromTheNameBasedOverloadsOnly()
    {
        // The compatibility wart, kept exactly where the compatibility obligation is. These overloads
        // have emitted "claims": [] since they shipped, to callers outside this repository, so changing
        // it is not this change's decision to make. The path-based builders above do not inherit it.
        Assert.Equal(0, TheOnlyCredential(Dcql.SdJwtVc(GenericPid))
            .GetProperty("claims").GetArrayLength());
        Assert.Equal(0, TheOnlyCredential(Dcql.Mdoc(MdlDocType, MdlNamespace))
            .GetProperty("claims").GetArrayLength());
    }

    [Fact]
    public void NoClaims_IsRefusedWhenTheQueryHasClaimSets()
    {
        // Here it is incoherent rather than merely non-conformant: a set must reference a claim, and
        // there is none to reference. §6.4.1 says as much outright, "claim_sets MUST NOT be present if
        // claims is absent".
        //
        // Asserting the message, not just the type. Without its own guard this input is still refused,
        // by the reference check further down, so a type-only assertion passes either way and says
        // nothing about which rule ran.
        var ex = Assert.Throws<ArgumentException>(
            () => Dcql.SdJwtVcByPath([GenericPid], [], ["age"]));

        Assert.Contains("at least one claim", ex.Message, StringComparison.Ordinal);
    }

    // Reported as a bad id, NOT as an unknown one. Both refusals are ArgumentException, so asserting
    // only the type passes with the guard removed: the lookup below it would refuse the same input
    // as "references ''", which reads as an empty string and sends the reader to the wrong claim.
    // The message is the whole reason this guard exists, so the message is what gets asserted.
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void AClaimSetHoldingSomethingThatIsNotAnId_IsRefusedAsSuch(string? id)
    {
        string[][] sets = [[id!]];

        var ex = Assert.ThrowsAny<ArgumentException>(() => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Id = "age", Path = ["age_over_18"] }], sets));

        Assert.DoesNotContain("references", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnEmptyClaimSet_IsRefused()
    {
        // The explicit array matters. A collection expression in a params position would read as
        // "no claim sets at all", which is a different call and does not throw.
        string[][] oneEmptySet = [[]];

        Refuses("claim set cannot be empty", () => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Id = "dob", Path = ["birthdate"] }], oneEmptySet));
    }

    // SPEC: §7.2. "A claims path pointer into an mdoc contains two elements of type string. The first
    // element refers to a namespace and the second element refers to a data element identifier." §7.2.1
    // step 1 makes it normative on the wallet: "If the claims path pointer does not contain exactly two
    // components or one of the components is not a string then abort processing and return an error."
    // So this builder must not be able to emit one, or it produces a query every conformant wallet
    // refuses, whose only symptom is a wallet returning nothing.
    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void AnMdocPathThatIsNotExactlyTwoSegments_IsRefused(int segments)
    {
        string[] path = [.. Enumerable.Range(0, segments).Select(n => $"segment{n}")];

        var ex = Assert.Throws<ArgumentException>(() => Dcql.MdocByPath(
            MdlDocType, [new DcqlClaim { Path = path }]));

        Assert.Contains("two segments", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnSdJwtVcPathMayBeAnyDepth_BecauseOnly72ConstrainsTheCount()
    {
        // The mirror of the test above, so the mdoc rule cannot be applied to the wrong format. §7.1
        // (JSON-based credentials) puts no length limit on a pointer.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GermanPid], [new DcqlClaim { Path = ["a", "b", "c"] }]));

        Assert.Equal(["a", "b", "c"], PathOf(credential.GetProperty("claims")[0]));
    }

    // SPEC: §6.3. The id "MUST be a non-empty string consisting of alphanumeric, underscore (_), or
    // hyphen (-) characters".
    [Theory]
    [InlineData("age 18")]
    [InlineData("age.18")]
    [InlineData("urn:age")]
    [InlineData("ålder")]
    public void AClaimIdOutsideTheAllowedCharacterSet_IsRefused(string id)
    {
        var ex = Assert.Throws<ArgumentException>(() => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Id = id, Path = ["age_over_18"] }], [id]));

        Assert.Contains("not a usable claim id", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("age_over_18")]
    [InlineData("age-18")]
    [InlineData("AGE18")]
    public void AClaimIdInsideTheAllowedCharacterSet_IsAccepted(string id)
    {
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Id = id, Path = ["age_over_18"] }], [id]));

        Assert.Equal(id, credential.GetProperty("claims")[0].GetProperty("id").GetString());
    }

    [Fact]
    public void AnIdWithNoClaimSetsAtAll_IsAccepted_Because63MakesItOptionalThen()
    {
        // The other side of the check below, and the side that is easy to break while writing it. SPEC:
        // §6.3 gives the id as "REQUIRED if claim_sets is present in the Credential Query; OPTIONAL
        // otherwise", and §6.4.1 says a query with no sets requests every claim, so nothing is
        // unreachable and an unreferenced id is merely unused. Easy to get wrong while writing the
        // reverse check below, because running that check unconditionally refuses this, and this is a
        // conformant query.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Id = "age", Path = ["age_over_18"] }]));

        Assert.Equal("age", credential.GetProperty("claims")[0].GetProperty("id").GetString());
        Assert.False(credential.TryGetProperty("claim_sets", out _));
    }

    [Fact]
    public void AClaimThatNoSetReferences_IsRefused_BecauseNothingWouldEverAskForIt()
    {
        // SPEC: §6.4.1. "If both claims and claim_sets are present, the Verifier requests one
        // combination of the claims listed in claim_sets." A claim outside every set is therefore never
        // requested. The query looks fine, the fallback silently cannot fire, and a holder who could
        // only satisfy that fallback returns nothing. This is the reverse of the dangling-reference
        // check and the easier of the two to write by accident.
        var ex = Assert.Throws<ArgumentException>(() => Dcql.SdJwtVcByPath(
            [GenericPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_over_18"] },
                new DcqlClaim { Id = "dob", Path = ["birthdate"] },
            ],
            ["age"]));

        Assert.Contains("in no claim set", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AClaimSetMayNameSeveralClaims_MeaningAllOfThemTogether()
    {
        // SPEC: §6.1. Claim_sets holds "arrays of identifiers for elements in claims that specifies
        // which COMBINATIONS of claims for the Credential are requested". A set is a combination, not a
        // single alternative, and every other test here uses one-id sets, so nothing pinned the plural
        // case: truncating a set to its first id was green across the whole suite.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_over_18"] },
                new DcqlClaim { Id = "dob", Path = ["birthdate"] },
            ],
            ["age", "dob"],
            ["dob"]));

        var first = credential.GetProperty("claim_sets")[0];
        Assert.Equal(2, first.GetArrayLength());
        Assert.Equal(["age", "dob"], first.EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public void IdMatchingIsCaseSensitive()
    {
        // §6.3 makes an id a string and says nothing about folding case, so "age" and "AGE" are two
        // ids. Matching them case-insensitively would accept a set whose reference resolves to nothing
        // on the wallet's side, which is the fail-open direction.
        Refuses("no claim in this query carries", () => Dcql.SdJwtVcByPath(
            [GenericPid], [new DcqlClaim { Id = "age", Path = ["age_over_18"] }], ["AGE"]));

        // And the same two ids coexist rather than colliding as duplicates.
        var credential = TheOnlyCredential(Dcql.SdJwtVcByPath(
            [GenericPid],
            [
                new DcqlClaim { Id = "age", Path = ["age_over_18"] },
                new DcqlClaim { Id = "AGE", Path = ["age_over_21"] },
            ],
            ["age"],
            ["AGE"]));

        Assert.Equal(2, credential.GetProperty("claims").GetArrayLength());
    }

    [Fact]
    public void TheNameBasedOverloadsEmitPathsOfTheRightLength()
    {
        // Every pre-existing assertion about these reads path[0] or path[1] by index, so lengthening a
        // path went unnoticed across the whole suite. That would corrupt every request this library has
        // ever sent, and for mdoc it would breach §7.2's two-element rule.
        var sdJwt = TheOnlyCredential(Dcql.SdJwtVc(GenericPid, "age_over_18"));
        Assert.Single(sdJwt.GetProperty("claims")[0].GetProperty("path").EnumerateArray());

        var mdoc = TheOnlyCredential(Dcql.Mdoc(MdlDocType, MdlNamespace, "age_over_18"));
        Assert.Equal(2, mdoc.GetProperty("claims")[0].GetProperty("path").GetArrayLength());
    }
}
