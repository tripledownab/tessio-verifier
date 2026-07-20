using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Tessio.Verifier.AspNetCore;

/// <summary>
/// Background worker that drains <see cref="DemoCompletionQueue"/> and, after
/// <see cref="VerifierOptions.DemoCompletionDelay"/>, completes each session with a synthesized DEMO result.
/// </summary>
internal sealed class DemoCompletionService : BackgroundService
{
    private readonly DemoCompletionQueue _queue;
    private readonly ISessionStore _store;
    private readonly TimeProvider _clock;
    private readonly VerifierOptions _options;

    public DemoCompletionService(
        DemoCompletionQueue queue,
        ISessionStore store,
        TimeProvider clock,
        IOptions<VerifierOptions> options)
    {
        _queue = queue;
        _store = store;
        _clock = clock;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var sessionId in _queue.DequeueAllAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                if (_options.DemoCompletionDelay > TimeSpan.Zero)
                {
                    await Task.Delay(_options.DemoCompletionDelay, _clock, stoppingToken).ConfigureAwait(false);
                }

                var result = DemoVerificationResultFactory.Create(_options);
                await _store.CompleteAsync(sessionId, result, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (KeyNotFoundException)
            {
                // Session was evicted or already completed/expired — nothing to do.
            }
        }
    }
}
