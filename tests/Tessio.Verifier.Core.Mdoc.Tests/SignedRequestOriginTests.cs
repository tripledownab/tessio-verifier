// What belongs in this file: which origins CreateSignedRequest signs for and which it refuses before
// signing, because the wallet would compute another transcript and the signature would not verify.
namespace Tessio.Verifier.Core.Mdoc.Tests;

public sealed class SignedRequestOriginTests : IDisposable
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";

    private readonly TestReaderCertificates _certificates = new();

    public void Dispose() => _certificates.Dispose();

    [Theory]
    [InlineData("")]
    [InlineData("verifier.example.com")]
    [InlineData("localhost:8080")]
    [InlineData("/etc/passwd")]
    [InlineData("javascript:alert(1)")]
    [InlineData("ftp://verifier.example.com")]
    [InlineData("https://verifier.example.com/")]
    [InlineData("https://verifier.example.com/page")]
    [InlineData("HTTPS://VERIFIER.EXAMPLE.COM")]
    [InlineData("https://verifier.example.com:443")]
    [InlineData("http://verifier.example.com:80")]
    [InlineData("https://verifier.example.com:0443")]
    [InlineData("https://verifier.example.com:08443")]
    [InlineData("https://verifier.example.com:70000")]
    [InlineData("https://verifier.example.com:65536")]
    [InlineData("https://verifier.example.com\n")]
    [InlineData("https://Verifier.example.com")]
    [InlineData("https://[::FFFF:7f00:1]")]
    [InlineData("android:apk-key-hash:a")]
    [InlineData("android:apk-key-hash:=")]
    [InlineData(" https://verifier.example.com")]
    [InlineData("https://bücher.example")]
    [InlineData("https://example\u3002com")]
    [InlineData("https://example.com\u200b")]
    [InlineData("https://[::ffff:127.0.0.1]")]
    [InlineData("android:apk-key-hash:abc ")]
    [InlineData("android:apk-key-hash:")]
    [InlineData("origin:https://verifier.example.com")]
    public void CreateSignedRequest_RefusesAnOriginNoBrowserReports(string origin)
    {
        Assert.ThrowsAny<ArgumentException>(() => Iso18013AnnexC.CreateSignedRequest(
            PidDocType, PidDocType, ["family_name"], origin, new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader]), null));
    }

    [Theory]
    [InlineData("https://verifier.example.com:8443")]
    [InlineData("http://localhost:8765")]
    [InlineData("https://xn--bcher-kva.example")]
    [InlineData("https://192.0.2.1")]
    [InlineData("https://my_host.example")]
    [InlineData("https://verifier.example.com.")]
    [InlineData("https://verifier.example.com:65535")]
    [InlineData("https://verifier.example.com:80")]
    [InlineData("http://verifier.example.com:443")]
    [InlineData("android:apk-key-hash:z5bU+XmRKF8IxXwm/wiqRx4KJMSG6CxcbAR0dOVeTkE")]
    [InlineData("android:apk-key-hash:z5bU+XmRKF8IxXwm/wiqRx4KJMSG6CxcbAR0dOVeTkE=")]
    [InlineData("https://[::ffff:7f00:1]")]
    [InlineData("https://[::1]:8443")]
    [InlineData("android:apk-key-hash:z5bUyXmRKF8IxXwm-wiqRx4KJMSG6CxcbAR0dOVeTkE")]
    public void CreateSignedRequest_AcceptsSerializedOrigins(string origin)
    {
        var request = Iso18013AnnexC.CreateSignedRequest(
            PidDocType, PidDocType, ["family_name"], origin, new MdocReaderKey(_certificates.ReaderKey, [_certificates.Reader]), null);

        Assert.NotNull(DeviceRequestReader.ReadSingleDocRequest(request.DeviceRequest).ReaderAuth);
    }
}
