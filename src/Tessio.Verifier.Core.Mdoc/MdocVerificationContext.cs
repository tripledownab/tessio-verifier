namespace Tessio.Verifier.Core.Mdoc;

/// <summary>
/// Per-verification context for mdoc presentations. Richer than the frozen
/// <see cref="VerificationContext"/> because the mdoc device signature covers the OpenID4VP
/// session transcript, which is built from more than a nonce.
/// </summary>
public sealed record MdocVerificationContext
{
    /// <summary>
    /// Expected document type from the DCQL query (e.g. <c>org.iso.18013.5.1.mDL</c>).
    /// When null, the docType check is skipped.
    /// </summary>
    public string? ExpectedDocType { get; init; }

    /// <summary>
    /// The <c>client_id</c> of the request this presentation answers, including any client
    /// identifier prefix. First element of the session transcript's handover info.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>The nonce of the request. Second element of the handover info.</summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// RFC 7638 SHA-256 thumbprint of the verifier's response-encryption JWK, when the response was
    /// encrypted; null for unencrypted responses. Third element of the handover info.
    /// </summary>
    public byte[]? EncryptionKeyThumbprint { get; init; }

    /// <summary>The <c>response_uri</c> of the request. Fourth element of the handover info.</summary>
    public string? ResponseUri { get; init; }

    /// <summary>
    /// An externally built session transcript. When set, device authentication is verified over
    /// exactly these bytes and none of the fields above are used to build one. Set it for
    /// presentations whose transcript this type cannot describe, such as ISO/IEC 18013-7 Annex C
    /// over the Digital Credentials API (<see cref="Iso18013AnnexCResponse.SessionTranscript"/>).
    /// </summary>
    public byte[]? SessionTranscript { get; init; }

    /// <summary>
    /// The zero knowledge request the presentation answers, or null. When it is set, a zero knowledge presentation
    /// must name one of the circuits it offered. Any other is refused before its proof is checked, even one the
    /// proof verifier accepts. Pass the same <see cref="Mdoc.ZkRequest"/> the request was built with. Null leaves
    /// the choice of circuit to <see cref="IZkProofVerifier.AcceptsCircuit"/> alone.
    /// </summary>
    /// <remarks>
    /// Only the offered circuits are enforced. <see cref="Mdoc.ZkRequest.Required"/> is not: a plain mdoc answer to
    /// a request that required a proof is verified as a plain presentation, as the age verification profile wants
    /// (Annex A, A.9). A presentation is matched by the circuit its identifier names, not by its spelling, so a
    /// bare hash or another casing of an offered circuit is accepted. The zero knowledge package's
    /// <c>LongfellowProofVerifier</c> takes the circuit's parameters from Longfellow's own specification for that
    /// hash, so with it the spelling carries nothing a proof depends on. A verifier that reads
    /// <see cref="ZkProofRequest.ZkSystemId"/> itself should read <see cref="ZkProofRequest.CircuitHash"/> instead.
    /// </remarks>
    // SPEC: Annex A, A.8 points the mechanism at ISO/IEC 18013-5 (Second Edition) section 10.2.7, which this library
    // could not read. Its CD working draft of 2025-09-14 (published by ISO/IEC JTC 1/SC 17/WG 10 in
    // github.com/ISOWG10/ISO-18013, Working Documents) says in 10.2.7: "ZkSystemId is an identifier set by the
    // mdoc reader that is used in the response to refer to a specific ZkSystemSpec as defined in the request." And
    // in 10.3.4: "ZkSystemId is used to indicate which ZKP system is used, by referencing one of the ZkSystemSpec
    // from the request." Read strictly, a response echoes the reader's string; matching by circuit is more
    // tolerant, as the remarks say. That draft is not the DIS A.8 cites.
    public ZkRequest? ZkRequest { get; init; }
}
