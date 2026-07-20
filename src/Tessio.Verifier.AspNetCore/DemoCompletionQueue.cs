using System.Threading.Channels;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// In-process queue of session ids awaiting DEMO auto-completion. The verifier's <c>/start</c> endpoint
/// enqueues; <see cref="DemoCompletionService"/> drains and completes them after the configured delay.
/// </summary>
internal sealed class DemoCompletionQueue
{
    private readonly Channel<string> _channel =
        Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });

    public ValueTask EnqueueAsync(string sessionId, CancellationToken ct = default) =>
        _channel.Writer.WriteAsync(sessionId, ct);

    public IAsyncEnumerable<string> DequeueAllAsync(CancellationToken ct) =>
        _channel.Reader.ReadAllAsync(ct);
}
