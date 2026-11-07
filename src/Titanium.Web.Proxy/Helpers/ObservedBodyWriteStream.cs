using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;

namespace Titanium.Web.Proxy.Helpers;

// Observes deframed wire bytes without reading or buffering the entire message.
internal sealed class ObservedBodyWriteStream(Stream destination, SessionEventArgs session, bool request) : Stream
{
    internal static async Task<byte[]> ObserveAsync(SessionEventArgs session, bool request,
        ReadOnlyMemory<byte> bytes, bool last)
    {
        var args = new BeforeBodyWriteEventArgs(session, bytes.ToArray(), true, last);
        if (request) await session.Server.OnBeforeRequestBodyWrite(args);
        else await session.Server.OnBeforeResponseBodyWrite(args);
        return args.BodyBytes ?? Array.Empty<byte>();
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var bytes = await ObserveAsync(session, request, buffer, false);
        if (bytes.Length > 0) await destination.WriteAsync(bytes, cancellationToken);
    }

    internal async Task CompleteAsync(CancellationToken cancellationToken)
    {
        var bytes = await ObserveAsync(session, request, ReadOnlyMemory<byte>.Empty, true);
        if (bytes.Length > 0) await destination.WriteAsync(bytes, cancellationToken);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override bool CanRead => false;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => destination.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => destination.FlushAsync(cancellationToken);
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
