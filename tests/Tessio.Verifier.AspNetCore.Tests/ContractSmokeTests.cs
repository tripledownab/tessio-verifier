using Tessio.Verifier.AspNetCore;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

public class ContractSmokeTests
{
    [Fact]
    public void ISessionStore_IsPublicInterface()
    {
        Assert.True(typeof(ISessionStore).IsInterface);
    }

    [Fact]
    public void VerificationSession_Pending_NoResult()
    {
        var now = DateTimeOffset.UtcNow;
        var request = new PresentationRequest.ByValue
        {
            ClientId = "https://verifier.example",
            Nonce = "n-0S6_WzA2Mj",
            AuthorizationRequestUri = new Uri("openid4vp://?request=eyJ..."),
            SignedRequestObject = "eyJ.signed.req",
            ExpiresAt = now.AddMinutes(2),
        };
        var session = new VerificationSession
        {
            SessionId = "sess-123",
            Request = request,
            Status = VerificationSessionStatus.Pending,
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(2),
        };
        Assert.Equal(VerificationSessionStatus.Pending, session.Status);
        Assert.Null(session.Result);
    }

    [Fact]
    public void VerificationSessionStatus_HasNoFailedValue()
    {
        var names = Enum.GetNames<VerificationSessionStatus>();
        Assert.Equal(3, names.Length);
        Assert.Contains("Pending", names);
        Assert.Contains("Completed", names);
        Assert.Contains("Expired", names);
        Assert.DoesNotContain("Failed", names);
    }
}
