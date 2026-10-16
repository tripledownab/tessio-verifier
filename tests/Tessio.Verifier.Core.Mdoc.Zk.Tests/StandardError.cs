using System.Runtime.InteropServices;

namespace Tessio.Verifier.Core.Mdoc.Zk.Tests;

/// <summary>
/// What belongs here: reading what native code writes to the process's standard error, which no .NET writer
/// sees because the library writes to file descriptor 2 directly (fprintf to stderr).
/// </summary>
internal static partial class StandardError
{
    private const int Descriptor = 2;

    /// <summary>Runs <paramref name="action"/> with descriptor 2 sent to a file and returns what reached it.</summary>
    /// <remarks>Every libc call is checked: a redirect that silently failed would read an empty file and pass.</remarks>
    public static async Task<string> CaptureAsync(Func<Task> action)
    {
        var path = Path.GetTempFileName();
        var saved = Checked(Dup(Descriptor));
        try
        {
            using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite))
            {
                Checked(Dup2((int)file.SafeFileHandle.DangerousGetHandle(), Descriptor));
                try
                {
                    await action();
                }
                finally
                {
                    Checked(Dup2(saved, Descriptor));
                }
            }

            return await File.ReadAllTextAsync(path);
        }
        finally
        {
            Checked(Close(saved));
            File.Delete(path);
        }
    }

    private static int Checked(int result) =>
        result >= 0 ? result : throw new InvalidOperationException($"A libc call failed with {Marshal.GetLastPInvokeError()}.");

    [LibraryImport("libc", EntryPoint = "dup", SetLastError = true)]
    private static partial int Dup(int descriptor);

    [LibraryImport("libc", EntryPoint = "dup2", SetLastError = true)]
    private static partial int Dup2(int from, int to);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int Close(int descriptor);
}
