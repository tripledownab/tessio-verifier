// What belongs here: that every public exception the shipped assemblies export makes its message one line,
// found by reflection. What one line means is MessageText's; each exception's own cases are its tests'.

using System.Reflection;
using Tessio.Verifier.Core.Mdoc;
using Tessio.Verifier.OpenId4Vp;

namespace Tessio.Verifier.AspNetCore.Tests;

/// <summary>
/// Every public exception the library throws carries a one-line message, whatever its constructor was
/// given. Found by reflection over the shipped assemblies, so a new public exception type is held to the
/// rule without anyone listing it.
/// </summary>
public sealed class PublicExceptionMessageTests
{
    // A value with every kind of break the rule removes: CR, LF, a C1 control, U+2028 and U+2029.
    private static readonly string Broken = "first\r\nsecond" + (char)0x85 + "third" + (char)0x2028 + "fourth" + (char)0x2029 + "fifth";

    private static readonly Assembly[] Shipped =
    [
        typeof(Tessio.Verifier.Trust.ITrustListResolver).Assembly,
        typeof(Tessio.Verifier.Core.ICredentialVerifier).Assembly,
        typeof(MdocProcessingException).Assembly,
        typeof(WalletResponseException).Assembly,
        typeof(ResponseEncryptionKeyProvider).Assembly,
    ];

    // Every public constructor of a public exception type that takes a message.
    private static IEnumerable<ConstructorInfo> Constructors() => Shipped
        .SelectMany(assembly => assembly.GetExportedTypes())
        .Where(type => typeof(Exception).IsAssignableFrom(type) && !type.IsAbstract)
        .SelectMany(type => type.GetConstructors())
        .Where(c => c.GetParameters().Any(p => p.Name == "message" && p.ParameterType == typeof(string)));

    public static TheoryData<ConstructorInfo> MessageConstructors()
    {
        var data = new TheoryData<ConstructorInfo>();
        foreach (var constructor in Constructors())
        {
            data.Add(constructor);
        }

        return data;
    }

    [Fact]
    public void The_scan_finds_the_exceptions_it_exists_for()
    {
        var types = Constructors().Select(c => c.DeclaringType).Distinct().ToList();

        Assert.Contains(typeof(WalletResponseException), types);
        Assert.Contains(typeof(MdocProcessingException), types);
    }

    [Theory]
    [MemberData(nameof(MessageConstructors))]
    public void A_message_that_quotes_a_line_break_leaves_on_one_line(ConstructorInfo constructor)
    {
        var arguments = constructor.GetParameters()
            .Select(p => p.Name == "message" ? Broken : p.ParameterType == typeof(string) ? "code" : (object)new InvalidOperationException("inner"))
            .ToArray();

        var message = ((Exception)constructor.Invoke(arguments)).Message;

        Assert.DoesNotContain(message, c => char.IsControl(c) || c is (char)0x2028 or (char)0x2029);
        Assert.Contains("second", message, StringComparison.Ordinal);
    }
}
