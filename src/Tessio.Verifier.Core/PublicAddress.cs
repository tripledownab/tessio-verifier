// What belongs here: deciding whether an IP address is on the public internet, and nothing about how
// a request reaches one. OutboundFetch applies it to every address a name resolves to, and then
// connects to exactly those addresses.

using System.Net;
using System.Net.Sockets;

namespace Tessio.Verifier.Core;

/// <summary>Whether an address is one an outbound fetch may reach.</summary>
/// <remarks>
/// IPv4 is "public unless in one of these ranges", from the IANA IPv4 special-purpose registry. IPv6 is
/// the other way round, because its special-purpose registry keeps growing and a list of exclusions
/// misses the next entry: only global unicast, 2000::/3, is public, minus the special ranges inside it.
/// Two forms carry an IPv4 address and are judged by it, because a gateway would deliver the request
/// there: IPv4-mapped addresses and the well-known NAT64 prefix. 6to4 is judged by its relay address.
/// </remarks>
internal static class PublicAddress
{
    internal static bool IsPublic(IPAddress address) => address.AddressFamily switch
    {
        AddressFamily.InterNetwork => IsPublicV4(address.GetAddressBytes()),
        AddressFamily.InterNetworkV6 => IsPublicV6(address.GetAddressBytes()),
        // Anything that is neither family is nothing a fetch intends to reach.
        _ => false,
    };

    private static bool IsPublicV4(ReadOnlySpan<byte> b) => b[0] switch
    {
        0 => false,                                   // "this network"
        10 => false,                                  // private
        100 when b[1] >= 64 && b[1] <= 127 => false,  // shared address space (carrier-grade NAT)
        127 => false,                                 // loopback
        169 when b[1] == 254 => false,                // link-local, including the cloud metadata address
        172 when b[1] >= 16 && b[1] <= 31 => false,   // private
        192 when b[1] == 0 && b[2] == 0 => false,     // IETF protocol assignments
        192 when b[1] == 0 && b[2] == 2 => false,     // documentation
        192 when b[1] == 88 && b[2] == 99 => false,   // deprecated 6to4 relay anycast
        192 when b[1] == 168 => false,                // private
        198 when b[1] == 18 || b[1] == 19 => false,   // benchmarking
        198 when b[1] == 51 && b[2] == 100 => false,  // documentation
        203 when b[1] == 0 && b[2] == 113 => false,   // documentation
        >= 224 => false,                              // multicast, reserved and broadcast
        _ => true,
    };

    private static bool IsPublicV6(ReadOnlySpan<byte> b)
    {
        // IPv4-mapped, ::ffff:0:0/96.
        if (b[..10].IndexOfAnyExcept((byte)0) < 0 && b[10] == 0xFF && b[11] == 0xFF)
        {
            return IsPublicV4(b[12..]);
        }

        // Well-known NAT64, 64:ff9b::/96: the last four bytes are the IPv4 destination. The local-use
        // NAT64 prefix, 64:ff9b:1::/48, places its IPv4 address by local convention, so it falls through
        // to the global unicast test below and is refused.
        if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B && b[4..12].IndexOfAnyExcept((byte)0) < 0)
        {
            return IsPublicV4(b[12..]);
        }

        // Global unicast only, 2000::/3. This refuses loopback, the unspecified address, unique local,
        // link-local, multicast, discard-only, IPv4-translated, SRv6 and every prefix not yet allocated.
        if ((b[0] & 0xE0) != 0x20) return false;

        if (b[0] == 0x20 && b[1] == 0x01 && b[2] < 0x02) return false;                // IETF protocol assignments, 2001::/23
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return false; // documentation, 2001:db8::/32
        if (b[0] == 0x3F && b[1] == 0xFF && (b[2] & 0xF0) == 0x00) return false;       // documentation, 3fff::/20

        // 6to4, 2002::/16: bytes two to five are the IPv4 relay.
        if (b[0] == 0x20 && b[1] == 0x02)
        {
            return IsPublicV4(b[2..6]);
        }

        return true;
    }
}
