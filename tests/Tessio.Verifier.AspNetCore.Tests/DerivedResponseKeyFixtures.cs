// What belongs here: the stand-ins the derived response-key tests share, a salt table, a clock and a
// response encrypted to a given key.
using System.Text.Json;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

internal static class DerivedResponseKeyFixtures
{
    public static WalletResponseData EncryptedResponse(ResponseEncryptionKeyProvider keys)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vp_token"] = new Dictionary<string, string[]> { ["credential"] = ["eyJoZWFkZXIifQ.eyJwYXlsb2FkIn0.c2ln~"] },
            ["state"] = "s",
        });

        return new WalletResponseData
        {
            ContentType = "application/x-www-form-urlencoded",
            Form = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                ["response"] = [EcdhEsJweEncryptor.Encrypt(payload, keys.PublicJwk.ToJsonString())],
            },
            Body = ReadOnlyMemory<byte>.Empty,
        };
    }
}

/// <summary>An in-memory salt store that records what it was asked, as a shared table would be asked.</summary>
internal sealed class SaltTable(StringComparer? kidComparer = null) : IResponseKeySaltStore
{
    private readonly Dictionary<string, (byte[] Salt, DateTimeOffset ExpiresAt)> _rows = new(kidComparer ?? StringComparer.Ordinal);

    public bool Failing { get; set; }

    public IEnumerable<string> Kids => _rows.Keys;

    public IReadOnlyDictionary<string, (byte[] Salt, DateTimeOffset ExpiresAt)> Rows => _rows;

    public List<string> Asked { get; } = [];

    /// <summary>Runs inside the next Find, before it answers.</summary>
    public Action<string>? DuringNextFind { get; set; }

    public void Save(string kid, byte[] salt, DateTimeOffset expiresAt)
    {
        if (Failing)
        {
            throw new IOException("The salt table is unavailable.");
        }

        _rows[kid] = (salt, expiresAt);
    }

    public (byte[] Salt, DateTimeOffset ExpiresAt)? Find(string kid)
    {
        Asked.Add(kid);
        var during = DuringNextFind;
        DuringNextFind = null;
        during?.Invoke(kid);
        return _rows.TryGetValue(kid, out var row) ? row : null;
    }
}

internal sealed class ManualClock : TimeProvider
{
    public DateTimeOffset Now { get; set; } = new(2026, 10, 21, 9, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => Now;
}
