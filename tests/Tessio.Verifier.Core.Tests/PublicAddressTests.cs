// What belongs here: which IP addresses an outbound fetch may reach, case by case. How a request gets
// to one is in OutboundFetchTests.

using System.Net;

namespace Tessio.Verifier.Core.Tests;

public class PublicAddressTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("2606:4700:4700::1111")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("64:ff9b::808:808")]     // NAT64 to 8.8.8.8
    [InlineData("2002:808:808::1")]      // 6to4 via 8.8.8.8
    [InlineData("2001:4860:4860::8888")] // a real resolver, inside 2001::/16 but outside 2001::/23
    [InlineData("2001:200::1")]          // the first address past 2001::/23
    [InlineData("2a00:1450::1")]         // RIPE region allocations
    [InlineData("2c0f:fb50::1")]         // AFRINIC, the top of the allocated space
    [InlineData("2620:fe::fe")]          // ARIN
    [InlineData("3ffe::1")]              // inside 2000::/3, outside 3fff::/20
    public void A_public_address_is_allowed(string address) =>
        Assert.True(PublicAddress.IsPublic(IPAddress.Parse(address)));

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("10.1.2.3")]
    [InlineData("100.64.0.1")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]      // the cloud metadata address
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.255")]
    [InlineData("192.0.2.1")]
    [InlineData("192.168.1.1")]
    [InlineData("198.18.0.1")]
    [InlineData("224.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("fc00::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("fe80::1")]
    [InlineData("fec0::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::1")]
    [InlineData("2001::1")]              // Teredo
    [InlineData("64:ff9b::a00:1")]       // NAT64 to 10.0.0.1
    [InlineData("64:ff9b:1::7f00:1")]    // local-use NAT64, which can embed 127.0.0.1
    [InlineData("::ffff:0:7f00:1")]      // IPv4-translated
    [InlineData("2002:a00:1::1")]        // 6to4 via 10.0.0.1
    [InlineData("192.88.99.1")]          // deprecated 6to4 relay
    [InlineData("100::1")]               // discard-only
    [InlineData("2001:2::1")]            // benchmarking
    [InlineData("2001:1ff:ffff::1")]     // the last /32 inside 2001::/23
    [InlineData("2001:10::1")]           // ORCHID
    [InlineData("2001:20::1")]           // ORCHIDv2
    [InlineData("3fff::1")]              // documentation
    [InlineData("5f00::1")]              // SRv6 SIDs
    [InlineData("4000::1")]              // not allocated
    public void A_non_public_address_is_refused(string address) =>
        Assert.False(PublicAddress.IsPublic(IPAddress.Parse(address)));
}
