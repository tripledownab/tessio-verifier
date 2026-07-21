using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// An <see cref="ISessionStore"/> that can look a session up by the OpenID4VP <c>state</c> value a
/// wallet echoes in its authorization response. The live callback path requires this: <c>state</c> is
/// the only correlation handle a wallet response carries.
/// </summary>
/// <remarks>
/// Implement this (not just <see cref="ISessionStore"/>) when replacing the default session store in a
/// deployment that receives real wallet callbacks. The built-in <see cref="InMemorySessionStore"/>
/// implements it; a distributed store typically keeps a state → session-id index next to the sessions.
/// </remarks>
public interface IStateCorrelatingSessionStore : ISessionStore
{
    /// <summary>
    /// Finds the pending session whose presentation request carries <paramref name="state"/>, or
    /// null when no such session exists (unknown, evicted, or replayed state).
    /// </summary>
    Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default);
}
