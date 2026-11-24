using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Tessio.Verifier.AspNetCore.Testing;
using Tessio.Verifier.Core;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;
using Tessio.Verifier.Trust;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// A deviceMac through each route's own key lookup: the redirect route finds the reader key in the
/// <see cref="ResponseEncryptionKeyStore"/> by the session's kid, and the Digital Credentials API route uses the
/// key its caller decrypted with. The MAC itself is proved against the published ISO/IEC 18013-5 Annex D example
/// (Core.Mdoc's DeviceMacTests); these prove the right key reaches it. Each host opts in
/// (<see cref="MdocVerifierOptions.AcceptDeviceMac"/>), as a deployment must.
/// </summary>
public sealed class DeviceMacRoundTripTests : IDisposable
{
    private const string Origin = "https://verifier.example";
    private const string MdlDocType = "org.iso.18013.5.1.mDL";
    private const string MdlNamespace = "org.iso.18013.5.1";
    private const string AvDocType = MockWalletResponses.EuAgeVerificationDocType;

    private static readonly string AvQuery =
        $$"""{"credentials":[{"id":"credential","format":"mso_mdoc","meta":{"doctype_value":"{{AvDocType}}"},"claims":[{"path":["{{AvDocType}}","age_over_18"]}]}]}""";

    private readonly MockWalletResponses _wallet = new();
    private readonly ECDsa _dcKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ServiceProvider _provider;

    /// <summary>The mdoc verifier a host registers to accept deviceMac; AddTessioVerifier's own refuses it.</summary>
    private static MdocVerifier AcceptingDeviceMac(IServiceProvider sp) => new(
        sp.GetRequiredService<ITrustListResolver>(), new MdocVerifierOptions { AcceptDeviceMac = true }, TimeProvider.System);

    public DeviceMacRoundTripTests()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITrustListResolver>(_ => new StaticTrustListResolver(
            [_wallet.MdocIssuerId], "test", [_wallet.MdocIacaCertificate]));
        services.AddSingleton(AcceptingDeviceMac);
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.CredentialFormat = MdocVerifier.Format;
            options.ResponseMode = ResponseMode.DirectPostJwt;
            options.RequestedClaims = ["age_over_18"];
        });
        _provider = services.BuildServiceProvider();
    }

    public void Dispose()
    {
        _provider.Dispose();
        _dcKey.Dispose();
        _wallet.Dispose();
    }

    private WalletResponseVerifier Verifier => (WalletResponseVerifier)_provider.GetRequiredService<IWalletResponseVerifier>();

    [Fact]
    public async Task Redirect_ADeviceMacKeyedToTheSessionsKey_Verifies()
    {
        var session = await SessionAsync(_provider.GetRequiredService<ResponseEncryptionKeyStore>());

        var result = await Verifier.VerifyAsync(session, _wallet.CreateEncryptedMdocMacResponse(session, MdlDocType, MdlNamespace));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task Redirect_AKeyTheStoreNoLongerHolds_RefusesTheDeviceMac()
    {
        // The session's key is minted by another store, so the verifier's store does not hold it: the state a request
        // is in once its key has expired. The response is opened with that key directly, as it would have been
        // before the key went.
        using var elsewhere = new ResponseEncryptionKeyStore(TimeProvider.System);
        var session = await SessionAsync(elsewhere);
        var parsed = await ParseWithAsync(elsewhere, session);

        var result = await Verifier.VerifyParsedAsync(session, parsed, CancellationToken.None);

        AssertNoReaderKey(result);
    }

    [Fact]
    public async Task Redirect_ACleartextRequestNamingAKey_RefusesADeviceMac()
    {
        // A cleartext request can still name a key in client_metadata. A deviceMac is accepted only for an encrypted
        // response, as on the Digital Credentials API route, so this one is refused for want of a key rather than
        // checked against that one.
        var keys = _provider.GetRequiredService<ResponseEncryptionKeyStore>();
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var cleartext = new VerifierOptions
        {
            CredentialFormat = options.CredentialFormat,
            ResponseMode = ResponseMode.DirectPost,
            RequestedClaims = options.RequestedClaims,
        };
        var session = await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(DemoRequestOptionsFactory.Create(
            cleartext,
            new Uri("https://verifier.example/verify/callback"),
            keys.CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk));
        var parsed = await ParseWithAsync(keys, session);

        var result = await Verifier.VerifyParsedAsync(session, parsed, CancellationToken.None);

        AssertNoReaderKey(result);
    }

    [Fact]
    public async Task Redirect_AStoreThatCannotDeriveTheKey_DoesNotFailADeviceSignature()
    {
        // The key is looked up for every encrypted mdoc, signed ones included. A store whose stored salt derives
        // nothing (ResponseEncryptionKeyStore.Get throws) must leave a deviceSignature answer as it was.
        using var broken = new ResponseEncryptionKeyStore(
            TimeProvider.System, new ResponseKeyDerivationOptions { Master = Enumerable.Repeat((byte)1, 32).ToArray(), Salts = new ShortSalts() });
        var services = new ServiceCollection();
        services.AddSingleton(broken);
        services.AddSingleton<ITrustListResolver>(_ => new StaticTrustListResolver(
            [_wallet.MdocIssuerId], "test", [_wallet.MdocIacaCertificate]));
        services.AddSingleton(AcceptingDeviceMac);
        services.AddTessioVerifier(options =>
        {
            options.Mode = VerifierMode.Mock;
            options.CredentialFormat = MdocVerifier.Format;
            options.ResponseMode = ResponseMode.DirectPostJwt;
            options.RequestedClaims = ["age_over_18"];
        });
        await using var provider = services.BuildServiceProvider();
        using var elsewhere = new ResponseEncryptionKeyStore(TimeProvider.System);
        var session = await SessionAsync(elsewhere);
        var signed = _wallet.CreateMdocResponse(
            session, docType: MdlDocType, mdocNamespace: MdlNamespace,
            encryptionKeyThumbprint: RequestParameters.TryGetEncryptionKeyThumbprint(session.Request));
        var parsed = await new WalletResponseParser(new WalletResponseParserOptions { PresentationFormat = MdocVerifier.Format })
            .ParseDetailedAsync(signed);

        var result = await ((WalletResponseVerifier)provider.GetRequiredService<IWalletResponseVerifier>())
            .VerifyParsedAsync(session, parsed, CancellationToken.None);

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task Redirect_AKeyDisposedAfterDecryption_RefusesTheDeviceMacRatherThanThrowing()
    {
        // The state of a key the store evicted, and so disposed, between the response's decryption and the copy.
        var keys = _provider.GetRequiredService<ResponseEncryptionKeyStore>();
        var session = await SessionAsync(keys);
        var parsed = await ParseWithAsync(keys, session);
        keys.Get(RequestParameters.TryGetEncryptionKeyId(session.Request))!.Dispose();

        var result = await Verifier.VerifyParsedAsync(session, parsed, CancellationToken.None);

        AssertNoReaderKey(result);
    }

    [Fact]
    public async Task DcApi_ADeviceMacKeyedToTheRequestsKey_Verifies()
    {
        var request = DcRequest(encrypted: true);

        var result = await Verifier.VerifyDcApiAsync(
            request, Origin, _wallet.CreateDcApiMdocMacResponse(request, Origin), new ECDsaSecurityKey(_dcKey));

        Assert.True(result.IsValid, string.Join("; ", result.Errors.Select(e => $"{e.Code}: {e.Message}")));
    }

    [Fact]
    public async Task DcApi_ACleartextRequest_RefusesADeviceMac()
    {
        // A cleartext request publishes no key, so no MAC can have been keyed to one the request named. Here the wallet
        // keys it to a key the caller holds and passes in anyway; it is still refused, because the request is what
        // decides which key a MAC may use.
        var request = DcRequest(encrypted: false);

        var result = await Verifier.VerifyDcApiAsync(
            request, Origin, _wallet.CreateDcApiMdocMacResponse(request, Origin, _dcKey.ExportParameters(false)),
            new ECDsaSecurityKey(_dcKey));

        AssertNoReaderKey(result);
    }

    private static void AssertNoReaderKey(VerificationResult result)
    {
        var error = Assert.Single(result.Errors);
        Assert.Equal(MdocErrorCodes.DeviceAuthInvalid, error.Code);
        Assert.Contains("reader key", error.Message, StringComparison.Ordinal);
    }

    /// <summary>A deviceMac answer to the session, opened with the session's key from <paramref name="keys"/>.</summary>
    private async Task<ParsedWalletResponse> ParseWithAsync(ResponseEncryptionKeyStore keys, VerificationSession session)
    {
        var key = keys.Get(RequestParameters.TryGetEncryptionKeyId(session.Request))!.DecryptionKey;
        return await new WalletResponseParser(new WalletResponseParserOptions
        {
            ResponseDecryptionKeyResolver = _ => key,
            PresentationFormat = MdocVerifier.Format,
        }).ParseDetailedAsync(_wallet.CreateEncryptedMdocMacResponse(session, MdlDocType, MdlNamespace));
    }

    /// <summary>Salts too short to derive from, so the store's lookup throws.</summary>
    private sealed class ShortSalts : IResponseKeySaltStore
    {
        public void Save(string kid, byte[] salt, DateTimeOffset expiresAt)
        {
        }

        public (byte[] Salt, DateTimeOffset ExpiresAt)? Find(string kid) => (new byte[1], DateTimeOffset.UtcNow.AddHours(1));
    }

    private async Task<VerificationSession> SessionAsync(ResponseEncryptionKeyStore keys)
    {
        var options = _provider.GetRequiredService<IOptions<VerifierOptions>>().Value;
        var jwk = keys.CreateForRequest(DateTimeOffset.UtcNow.AddMinutes(5)).PublicJwk;
        return await _provider.GetRequiredService<InMemorySessionStore>().CreateAsync(
            DemoRequestOptionsFactory.Create(options, new Uri("https://verifier.example/verify/callback"), jwk));
    }

    private DcApiPresentationRequest DcRequest(bool encrypted)
    {
        var p = _dcKey.ExportParameters(false);
        var jwk = new JsonObject
        {
            ["kty"] = "EC",
            ["crv"] = "P-256",
            ["x"] = Base64UrlEncoder.Encode(p.Q.X!),
            ["y"] = Base64UrlEncoder.Encode(p.Q.Y!),
            ["use"] = "enc",
            ["alg"] = "ECDH-ES",
            ["kid"] = "1",
        };
        return new DcApiPresentationRequestBuilder().Build(new DcApiPresentationRequestOptions
        {
            Nonce = "nonce-1",
            DcqlQueryJson = AvQuery,
            EncryptedResponse = encrypted,
            ExpectedOrigins = [Origin],
            ClientMetadataJson = ClientMetadata.Build(MdocVerifier.Format, encrypted ? jwk : null),
        });
    }
}
