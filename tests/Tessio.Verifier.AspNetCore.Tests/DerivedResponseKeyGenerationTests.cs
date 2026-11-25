// What belongs here: ResponseEncryptionKeyStore built with ResponseKeyGenerationOptions, where the master is
// replaced over time and a key is found again with the generation its salt names. The single-master store is
// DerivedResponseKeyStoreTests'; the derivation itself is ResponseKeyDerivationTests'.
using System.Security.Cryptography;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class DerivedResponseKeyGenerationTests
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private readonly Masters _masters = new();
    private readonly GenerationSaltTable _salts = new();
    private readonly ManualClock _clock = new();

    public DerivedResponseKeyGenerationTests() => _masters.Add("g1");

    private ResponseEncryptionKeyStore Store(Masters? masters = null) =>
        new(_clock, new ResponseKeyGenerationOptions { Masters = masters ?? _masters, Salts = _salts });

    private static Task<ParsedWalletResponse> Open(ResponseEncryptionKeyStore store, ResponseEncryptionKeyProvider keys) =>
        new WalletResponseParser(new WalletResponseParserOptions { ResponseDecryptionKeyResolver = kid => store.Get(kid)?.DecryptionKey })
            .ParseDetailedAsync(DerivedResponseKeyFixtures.EncryptedResponse(keys));

    [Fact]
    public void A_new_key_derives_from_the_newest_generation_and_records_it()
    {
        _masters.Add("g2");
        using var store = Store();

        var kid = store.CreateForRequest(_clock.Now + Lifetime).KeyId;

        Assert.Equal("g2", _salts.Rows[kid].Generation);
    }

    [Fact]
    public async Task A_key_made_before_a_rotation_opens_after_it_on_another_instance()
    {
        using var first = Store();
        var before = first.CreateForRequest(_clock.Now + Lifetime);

        _masters.Add("g2");
        using var second = Store();
        var after = second.CreateForRequest(_clock.Now + Lifetime);

        Assert.Equal("s", (await Open(second, before)).State);
        Assert.Equal("s", (await Open(first, after)).State);
        Assert.Equal(["g1", "g2"], [_salts.Rows[before.KeyId].Generation, _salts.Rows[after.KeyId].Generation]);
    }

    [Fact]
    public void A_live_salt_whose_generation_is_gone_is_refused_by_name()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        _masters.Add("g2");
        _masters.Delete("g1");

        using var second = Store();
        var refused = Assert.Throws<ResponseKeyGenerationUnavailableException>(() => second.Get(kid));

        Assert.Equal("g1", refused.Generation);
        Assert.Contains("'g1'", refused.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_expired_salt_whose_generation_is_gone_is_no_key_rather_than_a_fault()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;
        _masters.Add("g2");
        _masters.Delete("g1");
        _clock.Now += Lifetime;

        using var second = Store();

        Assert.Null(second.Get(kid));
    }

    [Fact]
    public void A_generation_whose_master_differs_between_instances_is_refused_loudly()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;

        var elsewhere = new Masters();
        elsewhere.Add("g1");
        using var second = Store(elsewhere);
        var refused = Assert.Throws<InvalidOperationException>(() => second.Get(kid));

        Assert.IsNotType<ResponseKeyGenerationUnavailableException>(refused);
    }

    [Fact]
    public async Task The_generation_saved_is_the_one_the_key_was_derived_with_when_the_newest_changes_between_reads()
    {
        // Each call to Newest names the other generation, as a directory read just before and just after the
        // timer's write would. A store that read it twice would save one generation and derive with the other.
        _masters.Add("g2");
        _masters.Alternate = true;
        using var store = Store();

        for (var i = 0; i < 4; i++)
        {
            var keys = store.CreateForRequest(_clock.Now + Lifetime);
            using var other = Store();
            Assert.Equal("s", (await Open(other, keys)).State);
        }
    }

    [Fact]
    public void A_newest_generation_that_stops_being_an_id_is_refused_at_the_next_key_and_nothing_is_saved()
    {
        using var store = Store();
        _masters.Add("g 2");

        Assert.Throws<InvalidOperationException>(() => store.CreateForRequest(_clock.Now + Lifetime));
        Assert.Empty(_salts.Rows);
    }

    [Fact]
    public void An_expired_row_is_no_key_even_when_its_generation_is_corrupt()
    {
        using var store = Store();
        var kid = store.CreateForRequest(_clock.Now + Lifetime).KeyId;
        _salts.Rows[kid] = _salts.Rows[kid] with { Generation = "g 1" };
        _clock.Now += Lifetime;

        using var other = Store();

        Assert.Null(other.Get(kid));
    }

    [Fact]
    public void A_master_found_for_a_stored_generation_must_be_usable()
    {
        using var first = Store();
        var kid = first.CreateForRequest(_clock.Now + Lifetime).KeyId;

        var short_ = new Masters();
        short_.Add("g2");
        short_.Add("g1", new byte[ResponseKeyDerivation.MinimumMasterLength - 1]);
        short_.NewestIs("g2");
        using var second = Store(short_);

        Assert.ThrowsAny<ArgumentException>(() => second.Get(kid));
    }

    [Fact]
    public void A_stored_generation_that_is_not_an_id_is_a_corrupt_row()
    {
        using var store = Store();
        var kid = store.CreateForRequest(_clock.Now + Lifetime).KeyId;
        _salts.Rows[kid] = _salts.Rows[kid] with { Generation = "g 1" };

        using var other = Store();

        Assert.Throws<InvalidOperationException>(() => other.Get(kid));
    }

    [Theory]
    [InlineData("")]
    [InlineData("g/1")]
    [InlineData("g 1")]
    public void Masters_whose_newest_generation_is_not_an_id_stop_the_host_at_boot(string generation)
    {
        var masters = new Masters();
        masters.Add(generation);

        Assert.Throws<InvalidOperationException>(() => Store(masters));
    }

    [Fact]
    public void A_newest_master_of_zeros_stops_the_host_at_boot()
    {
        var masters = new Masters();
        masters.Add("g1", new byte[ResponseKeyDerivation.MinimumMasterLength]);

        Assert.ThrowsAny<ArgumentException>(() => Store(masters));
    }

    [Theory]
    [InlineData("20261125T0600Z", true)]
    [InlineData("g-1_a.b", true)]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", true)]
    [InlineData("", false)]
    [InlineData("g:1", false)]
    [InlineData("é", false)]
    public void Generation_ids_are_short_plain_tokens(string generation, bool valid)
    {
        Assert.Equal(valid, ResponseKeyGenerationOptions.IsGenerationId(generation));
        Assert.False(ResponseKeyGenerationOptions.IsGenerationId(new string('g', ResponseKeyGenerationOptions.MaximumGenerationLength + 1)));
    }

    /// <summary>Masters by generation, the newest last, as a directory of generation files would be read.</summary>
    private sealed class Masters : IResponseKeyMasters
    {
        private readonly List<(string Generation, byte[] Master)> _generations = [];
        private string? _newest;
        private int _reads;

        /// <summary>Newest names the last two generations in turn, one per call.</summary>
        public bool Alternate { get; set; }

        public void NewestIs(string generation) => _newest = generation;

        public void Add(string generation, byte[]? master = null) =>
            _generations.Add((generation, master ?? RandomNumberGenerator.GetBytes(ResponseKeyDerivation.MinimumMasterLength)));

        public void Delete(string generation) => _generations.RemoveAll(g => g.Generation == generation);

        public (string Generation, byte[] Master) Newest() =>
            _newest is not null ? _generations.First(g => g.Generation == _newest)
            : Alternate ? _generations[^(1 + (_reads++ % 2))]
            : _generations[^1];

        public byte[]? Find(string generation) => _generations.FirstOrDefault(g => g.Generation == generation).Master;
    }

    /// <summary>An in-memory salt store with generations, as a shared table with a generation column would be.</summary>
    private sealed class GenerationSaltTable : IResponseKeyGenerationSaltStore
    {
        public Dictionary<string, (byte[] Salt, string Generation, DateTimeOffset ExpiresAt)> Rows { get; } = new(StringComparer.Ordinal);

        public void Save(string kid, byte[] salt, string generation, DateTimeOffset expiresAt) => Rows[kid] = (salt, generation, expiresAt);

        public (byte[] Salt, string Generation, DateTimeOffset ExpiresAt)? Find(string kid) =>
            Rows.TryGetValue(kid, out var row) ? row : null;
    }
}
