// What belongs in this file: a derived response key used for a Digital Credentials API (Annex C) request,
// exactly as going-live.md shows it. The derivation itself is checked in ResponseKeyDerivationTests, the Annex C
// overload's rules in the Core.Mdoc tests.
using System.Security.Cryptography;
using Tessio.Verifier.Core.Mdoc;

namespace Tessio.Verifier.AspNetCore.Tests;

public sealed class DerivedAnnexCKeyTests
{
    private const string DocType = "eu.europa.ec.av.1";
    private const string Origin = "https://verifier.example.com";

    [Fact]
    public void A_request_built_around_a_derived_key_opens_with_the_key_derived_again()
    {
        var master = RandomNumberGenerator.GetBytes(32);
        var salt = RandomNumberGenerator.GetBytes(32);

        Iso18013AnnexCRequest request;
        using (var derived = ResponseKeyDerivation.Derive(master, salt))
        using (var responseKey = ECDiffieHellman.Create(derived.ExportParameters(includePrivateParameters: true)))
        {
            request = Iso18013AnnexC.CreateRequest(DocType, DocType, ["age_over_18"], zkRequest: null, responseKey);
        }

        var deviceResponse = "stand-in DeviceResponse bytes"u8.ToArray();
        var encryptedResponse = Iso18013AnnexC.SealResponse(deviceResponse, request.EncryptionInfo, Origin);

        // Another instance or this one after a restart: only the master and the stored salt are at hand.
        using var again = ResponseKeyDerivation.Derive(master, salt);
        using var key = ECDiffieHellman.Create(again.ExportParameters(includePrivateParameters: true));
        var opened = Iso18013AnnexC.OpenResponse(encryptedResponse, key.ExportPkcs8PrivateKey(), request.EncryptionInfo, Origin);

        Assert.Equal(deviceResponse, opened.DeviceResponse);
    }
}
