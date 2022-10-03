using System.Net.Sockets;
using VirtualVpn.Helpers;

namespace VirtualVpn.TlsWrappers;

/// <summary>
/// Stream abstraction over a network socket
/// </summary>
public class SocketStream : Stream
{
    private Socket? _socket;

    /// <summary>
    /// Create a stream wrapper for a socket
    /// </summary>
    /// <param name="socket">socket to wrap</param>
    public SocketStream(Socket socket)
    {
        Log.Trace(nameof(SocketStream));
        _socket = socket;
    }

    /// <summary>
    /// Underlying socket used by this stream
    /// </summary>
    public Socket? Socket => _socket;

    /// <summary>
    /// Dispose of stream and socket.
    /// </summary>
    ~SocketStream()
    {
        Log.Trace("~" + nameof(SocketStream));
        Dispose(false);
    }

    /// <summary>
    /// Releases the unmanaged resources used by the <see cref="T:System.IO.Stream"/> and optionally releases the managed resources.
    /// </summary>
    protected override void Dispose(bool disposing)
    {
        Log.Trace("SocketStream: Dispose");
        var sock = Interlocked.Exchange(ref _socket, null);
        if (sock is not null)
        {
            sock.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary> Does nothing </summary>
    public override void Flush()
    {
        Log.Trace("SocketStream: Flush");
    }

    /// <summary>
    /// Reads from the underlying socket into a provided buffer.
    /// </summary>
    /// <returns>
    /// The total number of bytes read into the buffer. This can be less than the number of bytes requested if that many bytes are not currently available, or zero (0) if the end of the stream has been reached.
    /// </returns>
    /// <param name="buffer">An array of bytes. When this method returns, the buffer contains the specified byte array with the values between <paramref name="offset"/> and (<paramref name="offset"/> + <paramref name="count"/> - 1) replaced by the bytes read from the current source. </param><param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin storing the data read from the current stream. </param><param name="count">The maximum number of bytes to be read from the current stream. </param><exception cref="T:System.ArgumentException">The sum of <paramref name="offset"/> and <paramref name="count"/> is larger than the buffer length. </exception><exception cref="T:System.ArgumentNullException"><paramref name="buffer"/> is null. </exception><exception cref="T:System.ArgumentOutOfRangeException"><paramref name="offset"/> or <paramref name="count"/> is negative. </exception><exception cref="T:System.IO.IOException">An I/O error occurs. </exception><exception cref="T:System.NotSupportedException">The stream does not support reading. </exception><exception cref="T:System.ObjectDisposedException">Methods were called after the stream was closed. </exception><filterpriority>1</filterpriority>
    public override int Read(byte[] buffer, int offset, int count)
    {
        Log.Trace($"SocketStream.{nameof(Read)}(buffer[{buffer.Length}], offset={offset}, count={count})");
        if (_socket == null) throw new InvalidOperationException("Attempted to read from a null socket");
        if (!_socket.Connected) throw new InvalidOperationException("Attempted to read from a disconnected socket");

        // SslStream REQUIRES us to be blocking on this call
        try
        {
            while (_socket is not null && _socket.Connected && _socket.Available < 1)
            {
                Thread.Sleep(50);
            }
        }
        catch (Exception ex)
        {
            Log.Error("SocketStream failed during wait for data", ex);
        }

        if (_socket == null) return 0;

        int len;
        try
        {
            len = _socket.Receive(buffer, offset, count, SocketFlags.None, out var err);
            if (err != SocketError.Success && err != SocketError.WouldBlock)
            {
                if (err == SocketError.TimedOut) throw new TimeoutException();
                throw new SocketException((int)err);
            }

            Log.Trace($"SocketStream.{nameof(Read)} got {len} bytes; err={err.ToString()}");
            Log.Trace(string.Join(" ", Bit.Describe("message", buffer.Take(512))));
        }
        catch (Exception ex)
        {
            Log.Error("SocketStream: Failed to read from underlying socket", ex);
            return 0;
        }

        Position += len;
        return len;
    }

    /// <summary>
    /// Writes a sequence of bytes to the underlying socket.
    /// </summary>
    /// <param name="buffer">An array of bytes. This method copies <paramref name="count"/> bytes from <paramref name="buffer"/> to the current stream. </param><param name="offset">The zero-based byte offset in <paramref name="buffer"/> at which to begin copying bytes to the current stream. </param><param name="count">The number of bytes to be written to the current stream. </param><filterpriority>1</filterpriority>
    public override void Write(byte[] buffer, int offset, int count)
    {
        Log.Trace($"SocketStream.{nameof(Write)}(buffer[{buffer.Length}], offset={offset}, count={count})");
        if (_socket == null) throw new InvalidOperationException("Attempted to read from a disconnected socket");
        _socket.Send(buffer, offset, count, SocketFlags.None, out var err);
        if (err != SocketError.Success)
        {
            if (err == SocketError.TimedOut)
                throw new TimeoutException();
            throw new SocketException((int)err);
        }

        _writtenLength += count;
    }

    long _writtenLength;

    /// <summary>
    /// Number of bytes written to socket
    /// </summary>
    public override long Length => _writtenLength;

    /// <summary>
    /// Number of bytes read from socket
    /// </summary>
    public override long Position { get; set; }

    /// <summary> No action </summary>
    public override long Seek(long offset, SeekOrigin origin)
    {
        Log.Trace($"SocketStream.{nameof(Seek)}");
        return 0;
    }

    /// <summary> No action </summary>
    public override void SetLength(long value)
    {
    }

    /// <summary> No action </summary>
    public override bool CanRead => true;

    /// <summary> No action </summary>
    public override bool CanSeek => false;

    /// <summary> No action </summary>
    public override bool CanWrite => true;
}