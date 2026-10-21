// What belongs here: how long a derived key lives in a store, from its fresh salt to its expiry, eviction
// and the store's disposal, and the race between two threads deriving the same key.
using System.Security.Cryptography;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class DerivedResponseKeyLifetimeTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private readonly ManualClock _clock = new();
    private readonly SaltTable _salts = new();
    private readonly byte[] _master = RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength);

    private ResponseEncryptionKeyStore Store() =>
        new(_clock, new ResponseKeyDerivationOptions { Master = _master, Salts = _salts });

    [Fact]
    public void Each_request_gets_its_own_full_length_salt_and_so_its_own_key()
    {
        using var store = Store();
        var a = store.CreateForRequest(_clock.Now + Lifetime).KeyId;
        var b = store.CreateForRequest(_clock.Now + Lifetime).KeyId;

        Assert.NotEqual(a, b);
        Assert.All(_salts.Rows.Values, row => Assert.Equal(32, row.Salt.Length));
        Assert.NotEqual(Convert.ToHexString(_salts.Rows[a].Salt), Convert.ToHexString(_salts.Rows[b].Salt));
    }

    [Fact]
    public void A_derived_again_key_expires_with_its_salt()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        using var second = Store();
        Assert.NotNull(second.Get(kid));

        _clock.Now += Lifetime;
        Assert.Null(second.Get(kid));
    }

    [Fact]
    public void An_instance_that_only_answers_callbacks_still_evicts_what_it_derived()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        using var second = Store();
        var held = second.Get(kid)!;

        // Any lookup that misses this instance's keys is a callback it answers; this kid names no key.
        _clock.Now += Lifetime + TimeSpan.FromSeconds(1);
        Assert.Null(second.Get("e4QLCKhjPQcfqwupeyQ1evM9zCxOUPb768lP7Y3QJgc"));

        Assert.Throws<ObjectDisposedException>(() => held.DecryptionKey.ECDsa.ExportParameters(false));
    }

    [Fact]
    public void A_disposed_store_neither_creates_nor_derives_a_key()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        var second = Store();
        second.Dispose();

        Assert.Throws<ObjectDisposedException>(() => second.CreateForRequest(_clock.Now + Lifetime));
        Assert.Throws<ObjectDisposedException>(() => second.Get(kid));
        Assert.Throws<ObjectDisposedException>(() => second.Get("not a kid"));
        Assert.DoesNotContain(kid, _salts.Asked);
    }

    [Fact]
    public async Task Disposing_while_a_request_is_created_never_yields_a_key_from_a_zeroed_master()
    {
        // The race is a matter of timing, so one round proves little; without the lock, this many fail.
        const int Rounds = 2000;
        var zeroMaster = new byte[ResponseKeyDerivation.MinimumMasterLength];
        for (var round = 0; round < Rounds; round++)
        {
            var store = Store();
            var creating = Task.Run(() =>
            {
                try
                {
                    return store.CreateForRequest(_clock.Now + Lifetime).KeyId;
                }
                catch (ObjectDisposedException)
                {
                    return null;
                }
            });
            store.Dispose();

            if (await creating is { } kid)
            {
                using var fromZero = new ResponseEncryptionKeyProvider(ResponseKeyDerivation.Derive(zeroMaster, _salts.Rows[kid].Salt));
                Assert.NotEqual(fromZero.KeyId, kid);
            }
        }
    }

    [Fact]
    public void The_thread_that_loses_a_race_to_derive_a_key_answers_with_the_winners()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        using var second = Store();
        ResponseEncryptionKeyProvider? winner = null;
        _salts.DuringNextFind = _ => winner = second.Get(kid);

        var answered = second.Get(kid);

        Assert.NotNull(winner);
        Assert.Same(winner, answered);
        // The loser disposes its own copy, never the one it answers with.
        _ = answered!.DecryptionKey.ECDsa.ExportParameters(false);
    }
}
