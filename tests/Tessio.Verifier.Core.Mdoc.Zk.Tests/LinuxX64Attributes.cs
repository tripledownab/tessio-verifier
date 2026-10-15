using System.Runtime.InteropServices;

namespace Tessio.Verifier.Core.Mdoc.Zk.Tests;

/// <summary>A test that needs libmdoc.so, which exists for Linux x64 only; skipped elsewhere, with the reason.</summary>
public sealed class LinuxX64FactAttribute : FactAttribute
{
    public LinuxX64FactAttribute() => Skip = LinuxX64.SkipReason;
}

/// <summary>The theory form of <see cref="LinuxX64FactAttribute"/>.</summary>
public sealed class LinuxX64TheoryAttribute : TheoryAttribute
{
    public LinuxX64TheoryAttribute() => Skip = LinuxX64.SkipReason;
}

internal static class LinuxX64
{
    public static string? SkipReason =>
        OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64
            ? null
            : "libmdoc.so is built for Linux x64 only.";
}
