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
    /// A built-in mock wallet issues freshly signed SD-JWT VC credentials and posts them through the
    /// full protocol pipeline (encrypted responses included). For integration tests; runs offline.
    /// </summary>
    Mock = 1,

    /// <summary>
    /// Replays the pinned RFC 9901 conformance vector (the specification's German PID example)
    /// through the real verifier and completes the session with the actual result. Proves the
    /// verifier against immutable, specification-published bytes; runs offline.
    /// </summary>
    Test = 2,
}
