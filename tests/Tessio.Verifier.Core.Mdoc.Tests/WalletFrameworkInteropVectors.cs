namespace Tessio.Verifier.Core.Mdoc.Tests;

/// <summary>
/// Cross-implementation interop fixture: the session transcript assembly and device authentication
/// in this DeviceResponse were built and COSE-signed by
/// WalletFramework.MdocLib 3.0.1 (OpenWallet Foundation wallet-framework-dotnet),
/// an independent mdoc implementation, over an OpenID4VP 1.0 Annex B.2.6.1 handover. Their parser
/// also accepted the issuer side our own builder produced. NEVER regenerate silently; this pins
/// cross-stack agreement on the SessionTranscript, DeviceAuthenticationBytes and COSE signing.
/// (Generating this fixture also surfaced a real transcript nonconformance in their 2.0.0 release,
/// fixed in 3.x: the two required nulls were omitted from SessionTranscript.)
/// </summary>
internal static class WalletFrameworkInteropVectors
{
    public const string ClientId = "x509_san_dns:interop.tessio.test";
    public const string Nonce = "interop-nonce-0001";
    public const string ResponseUri = "https://interop.tessio.test/callback";
    public const string DocType = "org.iso.18013.5.1.mDL";
    public const string DsSubject = "CN=Tessio Interop DS";

    public const string DeviceResponseBase64Url =
        """
        o2ZzdGF0dXMAZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGRldmljZVNp
        Z25lZKJqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhA3jw6XdCcsaCAe5ey4vLjcETgaGXmznxqPSqIfsrX
        zjZXPE_qmxiuF2yNjqz4cD1HJ9qetUIpJc2oyJaKwRUtimpuYW1lU3BhY2Vz2BhBoGxpc3N1ZXJTaWduZWSiamlzc3VlckF1
        dGjShEOhASahGCGCWQE7MIIBNzCB3aADAgECAhEAqE3oCoanlkWT_1UW8ZQkMzAKBggqhkjOPQQDAjAeMRwwGgYDVQQDExNU
        ZXNzaW8gSW50ZXJvcCBJQUNBMB4XDTI2MDcyMjE4MzIzNVoXDTQwMDcyMjE4MzczNVowHDEaMBgGA1UEAxMRVGVzc2lvIElu
        dGVyb3AgRFMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATrL-tzda7jYqRO-BZqrzXuHrjdc12HPPu82OPLS55UMmdteXeD
        neM7Xa6hwKGh7Z6ZE4isUuayBN9z33AobnC2MAoGCCqGSM49BAMCA0kAMEYCIQD5fE9awjZ0yAmgVvPBjHzdwM1n-ceJSBoS
        LmLWfoZPEwIhAICijgsnlKbKcrCVz3GJv9Knj047ciDru_88cfvAB9cZWQFIMIIBRDCB66ADAgECAggnXOrad1VLjDAKBggq
        hkjOPQQDAjAeMRwwGgYDVQQDExNUZXNzaW8gSW50ZXJvcCBJQUNBMB4XDTI2MDcyMjE4MzIzNVoXDTQxMDcyMjE4MzczNVow
        HjEcMBoGA1UEAxMTVGVzc2lvIEludGVyb3AgSUFDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLdi678W-RKUnVR8p_X0
        3b6AXhTwodFJ4HeH_N5pP6H3RbYJNy8oGSzmC4HH74W3AUbkl6EAGCLFGDK-uKxjKzOjEzARMA8GA1UdEwEB_wQFMAMBAf8w
        CgYIKoZIzj0EAwIDSAAwRQIhAPW48L66fYdowG4Z1mOLGO5dBe4-38PGx3Nn2CGENjiiAiBdZCX44CCcCjS85Zm2J-WaJ_VX
        Q74obkHvm8LD-T33OFkBf9gYWQF6pmdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGd2ZXJzaW9uYzEuMGx2YWxpZGl0
        eUluZm-jZnNpZ25lZMB0MjAyNi0wNy0yMlQxODozNzozNVppdmFsaWRGcm9twHQyMDI2LTA3LTIyVDE4OjMyOjM1Wmp2YWxp
        ZFVudGlswHQyMDM2LTA3LTIyVDE4OjM3OjM1Wmx2YWx1ZURpZ2VzdHOhcW9yZy5pc28uMTgwMTMuNS4xogBYIAvrZdTv4kln
        s5aBi7XddfGLWMyIlvNjvZISuWQWVnI3AVggPmZ0msGd4_CavV0O8pdZlRe_iYxYhdw2TcPy9xOsQ1ttZGV2aWNlS2V5SW5m
        b6FpZGV2aWNlS2V5pAECIAEhWCCEgHxXQY7Xm0-Gpm3vsgh2Wssqm5lg69aB3MmYBJHUHyJYIEpK_J-JWCm9IJefm7UGKcU-
        TWE_Hikz9dH87zagpKNvb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2WEAZrxwuhXImeBUecBcqIr0E1XubcwoINIW1Zen813pE
        SJH2FCI17Xwi2RZSx5KKcrKFaaqurs4-0xsx8Tp4yCKAam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWFakZnJh
        bmRvbVDD1KNX5vcrJaNDp_-7foDiaGRpZ2VzdElEAGxlbGVtZW50VmFsdWVnSW50ZXJvcHFlbGVtZW50SWRlbnRpZmllcmtm
        YW1pbHlfbmFtZdgYWE-kZnJhbmRvbVCFcRmH1anaSX2PTgx0KEYkaGRpZ2VzdElEAWxlbGVtZW50VmFsdWX1cWVsZW1lbnRJ
        ZGVudGlmaWVya2FnZV9vdmVyXzE4
        """;

    public const string IacaCertificateHex =
        """
        308201443081EBA0030201020208275CEADA77554B8C300A06082A8648CE3D040302301E311C301A0603550403131354
        657373696F20496E7465726F702049414341301E170D3236303732323138333233355A170D3431303732323138333733
        355A301E311C301A0603550403131354657373696F20496E7465726F7020494143413059301306072A8648CE3D020106
        082A8648CE3D03010703420004B762EBBF16F912949D547CA7F5F4DDBE805E14F0A1D149E07787FCDE693FA1F745B609
        372F28192CE60B81C7EF85B70146E497A1001822C51832BEB8AC632B33A3133011300F0603551D130101FF0405300301
        01FF300A06082A8648CE3D0403020348003045022100F5B8F0BEBA7D8768C06E19D6638B18EE5D05EE3EDFC3C6C77367
        D821843638A202205D6425F8E0209C0A34BCE599B627E59A27F55743BE286E41EF9BC2C3F93DF738
        """;

    public static string DeviceResponse => DeviceResponseBase64Url.ReplaceLineEndings(string.Empty).Replace(" ", string.Empty);

    public static byte[] IacaCertificate =>
        Convert.FromHexString(string.Concat(IacaCertificateHex.Where(char.IsAsciiHexDigit)));
}
