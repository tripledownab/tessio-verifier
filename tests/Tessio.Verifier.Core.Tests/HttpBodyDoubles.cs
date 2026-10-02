// What belongs here: HTTP response bodies that misbehave in one specific way each, for testing how
// the outbound fetch rules treat them.

using System.Net;

namespace Tessio.Verifier.Core.Tests;

internal sealed class UnseekableStream(byte[] content) : MemoryStream(content)
{
    public override bool CanSeek => false;
}

internal sealed class BreakingBodyHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new BreakingStream()) });
}

/// <summary>Fails its first read the way a dropped connection does.</summary>
internal sealed class BreakingStream : MemoryStream
{
    public override bool CanSeek => false;

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
        ValueTask.FromException<int>(new IOException("The response ended prematurely."));
}

internal sealed class StallingBodyHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StallingStream()) });
}

/// <summary>Never yields a byte, and returns only when its read is cancelled.</summary>
internal sealed class StallingStream : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => 0; set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        await Task.Delay(Timeout.Infinite, ct).ConfigureAwait(false);
        return 0;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
        ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}

internal sealed class DeclaredLengthHandler(long declared) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new UnreadableContent(declared) });
}

internal sealed class UnreadableContent : HttpContent
{
    public UnreadableContent(long declared) => Headers.ContentLength = declared;

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        throw new InvalidOperationException("The body was read, so the declared length was not checked.");

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}
