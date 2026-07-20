namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Operating mode for the Tessio verifier. Because no production EUDI wallets ship yet, these modes
/// let a developer exercise the full request/session/result flow without a real wallet.
/// </summary>
public enum VerifierMode
{
    /// <summary>
    /// Auto-completes each session locally with a synthesized, valid result after a short delay.
    /// For showcases and the first-run experience — no wallet, no protocol traffic.
    /// </summary>
    Demo = 0,

    /// <summary>
    /// Returns canned wallet responses for predictable integration tests. Reserved for a later slice;
    /// currently behaves like <see cref="Demo"/> until the OpenID4VP response path is wired.
    /// </summary>
    Mock = 1,

    /// <summary>
    /// Full protocol compliance against fixtures / conformance vectors. Reserved for a later slice.
    /// </summary>
    Test = 2,
}
