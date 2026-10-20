using Tessio.Verifier.Core;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

// Host stores the same-device tests stand in for, each the built-in store with one capability taken away.

/// <summary>A store written before the same-device interface existed: correlates by state, holds nothing.</summary>
internal sealed class CrossDeviceOnlyStore(InMemorySessionStore inner) : IStateCorrelatingSessionStore
{
    public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
        inner.CreateAsync(options, ct);

    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) => inner.GetAsync(sessionId, ct);

    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) =>
        inner.FindByStateAsync(state, ct);

    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) =>
        inner.CompleteAsync(sessionId, result, ct);
}

/// <summary>A same-device store with a defect: it keeps the session and its request, and drops the binding.</summary>
internal sealed class BindingLosingStore(InMemorySessionStore inner) : ISameDeviceSessionStore
{
    public Task<VerificationSession> CreateBoundAsync(
        PresentationRequestOptions options, byte[] browserBinding, CancellationToken ct = default) =>
        inner.CreateAsync(options, ct);

    public Task<SameDeviceHold> HoldAsync(
        string sessionId, VerificationResult result, byte[] responseCodeHash, DateTimeOffset redeemBy,
        CancellationToken ct = default) =>
        inner.HoldAsync(sessionId, result, responseCodeHash, redeemBy, ct);

    public Task<SameDeviceRedemption> RedeemAsync(
        string sessionId, byte[] responseCodeHash, byte[] browserBinding, CancellationToken ct = default) =>
        inner.RedeemAsync(sessionId, responseCodeHash, browserBinding, ct);

    public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
        inner.CreateAsync(options, ct);

    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) => inner.GetAsync(sessionId, ct);

    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) =>
        inner.FindByStateAsync(state, ct);

    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) =>
        inner.CompleteAsync(sessionId, result, ct);
}

/// <summary>The built-in store, recording every browser binding a redemption hands it.</summary>
internal sealed class BindingRecordingStore(InMemorySessionStore inner) : ISameDeviceSessionStore
{
    public List<byte[]> RedeemedWith { get; } = [];

    public Task<SameDeviceRedemption> RedeemAsync(
        string sessionId, byte[] responseCodeHash, byte[] browserBinding, CancellationToken ct = default)
    {
        RedeemedWith.Add(browserBinding);
        return inner.RedeemAsync(sessionId, responseCodeHash, browserBinding, ct);
    }

    public Task<VerificationSession> CreateBoundAsync(
        PresentationRequestOptions options, byte[] browserBinding, CancellationToken ct = default) =>
        inner.CreateBoundAsync(options, browserBinding, ct);

    public Task<SameDeviceHold> HoldAsync(
        string sessionId, VerificationResult result, byte[] responseCodeHash, DateTimeOffset redeemBy,
        CancellationToken ct = default) =>
        inner.HoldAsync(sessionId, result, responseCodeHash, redeemBy, ct);

    public Task<VerificationSession> CreateAsync(PresentationRequestOptions options, CancellationToken ct = default) =>
        inner.CreateAsync(options, ct);

    public Task<VerificationSession?> GetAsync(string sessionId, CancellationToken ct = default) => inner.GetAsync(sessionId, ct);

    public Task<VerificationSession?> FindByStateAsync(string state, CancellationToken ct = default) =>
        inner.FindByStateAsync(state, ct);

    public Task CompleteAsync(string sessionId, VerificationResult result, CancellationToken ct = default) =>
        inner.CompleteAsync(sessionId, result, ct);
}
