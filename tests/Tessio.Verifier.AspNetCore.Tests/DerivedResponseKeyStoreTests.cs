// What belongs here: ResponseEncryptionKeyStore built with ResponseKeyDerivationOptions, where a key is
// found again from its stored salt by another store instance. The derivation itself is
// ResponseKeyDerivationTests'.
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class DerivedResponseKeyStoreTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private readonly byte[] _master = RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength);
    private readonly SaltTable _salts = new();
    private readonly ManualClock _clock = new();

    private ResponseEncryptionKeyStore Store(byte[]? master = null) =>
        new(_clock, new ResponseKeyDerivationOptions { Master = master ?? _master, Salts = _salts });

    [Fact]
    public async Task Another_instance_decrypts_a_response_encrypted_to_the_first_ones_key()
    {
        using var first = Store();
        var keys = first.CreateForRequest(_clock.Now + Lifetime);
        var response = DerivedResponseKeyFixtures.EncryptedResponse(keys);

        using var second = Store();
        var parsed = await new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKeyResolver = kid => second.Get(kid)?.DecryptionKey,
        }).ParseDetailedAsync(response);

        Assert.Equal("s", parsed.State);
        // Derived once and then held, as a generated key is.
        Assert.Same(second.Get(keys.KeyId), second.Get(keys.KeyId));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_registered_store_replaces_the_default_whichever_side_of_AddTessioVerifier_it_is_on(bool registeredFirst)
    {
        // Two hosts sharing the salts, as two instances of one deployment do. The key is made where the
        // start endpoint makes it and resolved by the parser the host registers.
        await using var first = Host(registeredFirst);
        await using var second = Host(registeredFirst);
        var keys = first.GetRequiredService<ResponseEncryptionKeyStore>().CreateForRequest(_clock.Now + Lifetime);

        var parsed = await second.GetRequiredService<WalletResponseParser>().ParseDetailedAsync(DerivedResponseKeyFixtures.EncryptedResponse(keys));

        Assert.Equal("s", parsed.State);
    }

    [Fact]
    public void A_salt_under_another_master_is_refused_loudly()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;

        using var other = Store(RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength));
        var refused = Assert.Throws<InvalidOperationException>(() => other.Get(kid));
        Assert.Contains("master", refused.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ResponseKeyDerivation.MinimumSaltLength - 1)]
    [InlineData(-1)]
    public void A_stored_salt_missing_or_too_short_to_derive_from_is_refused_loudly(int length)
    {
        using var store = Store();
        const string kid = "e4QLCKhjPQcfqwupeyQ1evM9zCxOUPb768lP7Y3QJgc";
        _salts.Save(kid, length < 0 ? null! : new byte[length], _clock.Now + Lifetime);

        Assert.Throws<InvalidOperationException>(() => store.Get(kid));
    }

    [Fact]
    public void An_expired_or_absent_salt_finds_no_key()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        using var second = Store();

        Assert.Null(second.Get("not-a-stored-kid"));
        _clock.Now += Lifetime;
        Assert.Null(second.Get(kid));
    }

    [Fact]
    public void A_salt_that_cannot_be_saved_fails_the_request_and_leaves_no_key()
    {
        _salts.Failing = true;
        using var store = Store();

        Assert.Throws<IOException>(() => store.CreateForRequest(_clock.Now + Lifetime));
        _salts.Failing = false;
        Assert.Empty(_salts.Kids);
    }

    [Fact]
    public void The_master_is_copied_so_changing_the_callers_array_changes_nothing()
    {
        var master = (byte[])_master.Clone();
        using var first = Store(master);
        master[0] ^= 1;
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;

        using var second = Store();
        Assert.Equal(kid, second.Get(kid)!.KeyId);
    }

    [Fact]
    public void A_master_below_the_minimum_or_all_zeros_is_refused_at_construction()
    {
        Assert.Throws<ArgumentException>(() => Store(RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength - 1)));
        Assert.Throws<ArgumentException>(() => Store(new byte[ResponseKeyDerivation.MinimumMasterLength]));
        var oneBitSet = new byte[ResponseKeyDerivation.MinimumMasterLength];
        oneBitSet[^1] = 1;
        using (Store(oneBitSet))
        {
        }
    }

    [Fact]
    public void Without_derivation_another_instance_finds_nothing_and_nothing_is_saved()
    {
        using var first = new ResponseEncryptionKeyStore(_clock);
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;

        using var second = new ResponseEncryptionKeyStore(_clock);
        Assert.Null(second.Get(kid));
        Assert.Empty(_salts.Kids);
    }

    private ServiceProvider Host(bool registeredFirst)
    {
        var services = new ServiceCollection();
        void Register() => services.AddSingleton(_ => Store());
        if (registeredFirst)
        {
            Register();
        }

        services.AddTessioVerifier(_ => { });
        if (!registeredFirst)
        {
            Register();
        }

        return services.BuildServiceProvider();
    }
}
