using System.Security.Cryptography;
using Tessio.Verifier.Core;

namespace Tessio.Verifier.AspNetCore;

// One session's state and its change signals: what InMemorySessionStore holds per session.
public sealed partial class InMemorySessionStore
{
    private sealed class SessionEntry
    {
        private readonly object _gate = new();
        private VerificationSession _current;
        private TaskCompletionSource<VerificationSession> _changed = NewSignal();
        private readonly byte[]? _browserBinding;
        private HeldPresentation? _held;

        /// <param name="initial">The session as created.</param>
        /// <param name="browserBinding">The binding hash of a same-device session, or null for a cross-device one.</param>
        public SessionEntry(VerificationSession initial, byte[]? browserBinding)
        {
            _current = initial;
            _browserBinding = browserBinding;
        }

        public TaskCompletionSource<VerificationSession> Terminal { get; } = NewSignal();

        public VerificationSession Current
        {
            get { lock (_gate) { return _current; } }
        }

        /// <summary>The session as it is now if it differs from <paramref name="seen"/>, else the next change.</summary>
        public Task<VerificationSession> NextChangeAfter(VerificationSession seen)
        {
            lock (_gate)
            {
                return ReferenceEquals(_current, seen) ? _changed.Task : Task.FromResult(_current);
            }
        }

        public void Complete(VerificationResult result)
        {
            lock (_gate)
            {
                if (_current.Status != VerificationSessionStatus.Pending)
                {
                    return;
                }

                Publish(_current with { Status = VerificationSessionStatus.Completed, Result = result });
                Terminal.TrySetResult(_current);
            }
        }

        public void RecordFailure(VerificationResult failure)
        {
            lock (_gate)
            {
                if (_current.Status != VerificationSessionStatus.Pending)
                {
                    return;
                }

                Publish(_current with { LastFailure = failure, FailedAttempts = _current.FailedAttempts + 1 });
            }
        }

        public bool IsBound => _browserBinding is not null;

        public SameDeviceHold Hold(VerificationResult result, byte[] responseCodeHash, DateTimeOffset redeemBy, DateTimeOffset now)
        {
            lock (_gate)
            {
                if (_current.Status != VerificationSessionStatus.Pending || (_held is { } held && now < held.RedeemBy))
                {
                    return SameDeviceHold.NotPending;
                }

                _held = new HeldPresentation(result, responseCodeHash, redeemBy);
                return SameDeviceHold.Held;
            }
        }

        public SameDeviceRedemption Redeem(byte[] responseCodeHash, byte[] browserBinding, DateTimeOffset now)
        {
            lock (_gate)
            {
                if (_current.Status != VerificationSessionStatus.Pending
                    || _held is not { } held
                    || now >= held.RedeemBy
                    || !CryptographicOperations.FixedTimeEquals(held.ResponseCodeHash, responseCodeHash))
                {
                    return SameDeviceRedemption.NotHeld;
                }

                _held = null;
                if (_browserBinding is null || !CryptographicOperations.FixedTimeEquals(_browserBinding, browserBinding))
                {
                    return SameDeviceRedemption.BindingMismatch;
                }

                Complete(held.Result);
                return SameDeviceRedemption.Redeemed;
            }
        }

        public VerificationSession Expire()
        {
            lock (_gate)
            {
                if (_current.Status == VerificationSessionStatus.Pending)
                {
                    Publish(_current with { Status = VerificationSessionStatus.Expired });
                    Terminal.TrySetResult(_current);
                }

                return _current;
            }
        }

        // Called under _gate. Replaces the signal before releasing the old one, so a waiter woken here
        // that asks again waits for the NEXT change rather than returning this one twice.
        private void Publish(VerificationSession next)
        {
            _current = next;
            var released = _changed;
            _changed = NewSignal();
            released.TrySetResult(next);
        }

        private static TaskCompletionSource<VerificationSession> NewSignal() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private sealed record HeldPresentation(VerificationResult Result, byte[] ResponseCodeHash, DateTimeOffset RedeemBy);
    }
}
