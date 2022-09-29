namespace VirtualVpn.TlsWrappers;

/// <summary>
/// A buffer with separate input/output, that is driven
/// BOTH asynchronously (using <see cref="WriteIncomingNonBlocking"/> and <see cref="ReadNonBlocking"/> methods),
/// AND in a blocking synchronous manner using the Stream interface.
/// </summary>
public class BlockingBidirectionalBuffer : Stream
{
    // Message buffers (encrypted)
    private readonly List<byte> _outgoingQueue;
    private int _outgoingQueueSent;
    private readonly List<byte> _incomingQueue;
    private int _incomingQueueRead;
    
    // latch used to make the Stream interface blocking
    private readonly AutoResetEvent _incomingDataLatch;
    
    // thread lock
    private readonly object _transferLock = new();

    /// <summary>
    /// Create a new, empty, bi-directional buffer.
    /// </summary>
    public BlockingBidirectionalBuffer()
    {
        _incomingDataLatch = new AutoResetEvent(false);
        _outgoingQueueSent = 0;

        _outgoingQueue = new List<byte>();
        _incomingQueue = new List<byte>();
    }
    
    /// <summary>
    /// Number of bytes waiting on the 'Outgoing' side, to be read by <see cref="ReadNonBlocking"/>
    /// </summary>
    public int Available => _outgoingQueueSent < _outgoingQueue.Count ? _outgoingQueue.Count - _outgoingQueueSent : 0;
    
    
    /// <summary>
    /// Write data to the 'incoming' queue, as read by the blocking
    /// <see cref="Read"/> method.
    /// </summary>
    public int WriteIncomingNonBlocking(byte[] buffer, int offset, int length)
    {
        Log.Trace("BlockingBidirectionalBuffer: IncomingFromTunnel");
        lock (_transferLock)
        {
            if (length <= 0) return 0;

            long bytesToStore = length;
            long available = buffer.Length - offset;
            if (bytesToStore > available) bytesToStore = available;

            Log.Trace($"BlockingBidirectionalBuffer: IncomingFromTunnel, adding {bytesToStore} bytes");
            if (offset == 0 && bytesToStore == buffer.Length)
            {
                _incomingQueue.AddRange(buffer);
            }
            else
            {
                _incomingQueue.AddRange(buffer.Skip(offset).Take((int)bytesToStore));
            }

            Log.Trace("BlockingBidirectionalBuffer: Releasing lock on incoming data");
            _incomingDataLatch.Set();
            return (int)bytesToStore;
        }
    }
    
    /// <summary>
    /// Pre-fill data to the 'outgoing' queue, as read by the non-blocking
    /// <see cref="ReadNonBlocking"/> method.
    /// </summary>
    public void WriteOutgoingNonBlocking(byte[] buffer)
    {
        Log.Trace("BlockingBidirectionalBuffer: WriteOutgoingNonBlocking");
        lock (_transferLock)
        {
            Log.Trace($"BlockingBidirectionalBuffer: WriteOutgoingNonBlocking, adding {buffer.Length} bytes");
            _outgoingQueue.AddRange(buffer);
        }
    }

    /// <summary>
    /// Read data from the 'outgoing' queue, as written by the blocking
    /// <see cref="Write"/> method.
    /// </summary>
    public int ReadNonBlocking(byte[] buffer)
    {
        lock (_transferLock)
        {
            var available = _outgoingQueue.Count - _outgoingQueueSent;

            if (available < 1) return 0;

            var end = buffer.Length;
            if (end > available) end = available;

            for (int i = 0; i < end; i++)
            {
                buffer[i] = _outgoingQueue[_outgoingQueueSent++];
            }

            if (_outgoingQueueSent >= _outgoingQueue.Count)
            {
                _outgoingQueueSent = 0;
                _outgoingQueue.Clear();
            }

            return end;
        }
    }
    
    /// <summary>
    /// BLOCKING: Waits for outgoing queue to empty
    /// </summary>
    public override void Flush()
    {
        Log.Trace("BlockingBidirectionalBuffer: Flush (wait)");
        while (_outgoingQueue.Count > 0)
        {
            Thread.Sleep(50);
        }
        Log.Trace("BlockingBidirectionalBuffer: Flush complete");
    }

    /// <summary>
    /// BLOCKING: Wait for data to be available in the incoming queue,
    /// then feed as much as possible into the buffer.
    /// This is written by the non-blocking <see cref="WriteIncomingNonBlocking"/> method.
    /// </summary>
    public override int Read(byte[] buffer, int offset, int count)
    {
        Log.Trace("BlockingBidirectionalBuffer: Read (wait)");
        _incomingDataLatch.WaitOne();
        Log.Trace("BlockingBidirectionalBuffer: Read (release)");

        lock (_transferLock)
        {
            var available = _incomingQueue.Count - _incomingQueueRead;
            var bytesToCopy = available > count ? count : available;

            if (bytesToCopy < 1)
            {
                Log.Trace("BlockingBidirectionalBuffer: Read, triggered with zero bytes");
                return 0;
            }

            Log.Trace($"BlockingBidirectionalBuffer: Read (copying {bytesToCopy} bytes)");
            for (int i = 0; i < bytesToCopy; i++)
            {
                buffer[i+offset] = _incomingQueue[_incomingQueueRead++];
            }

            if (_incomingQueueRead >= _incomingQueue.Count)
            {
                _incomingQueue.Clear();
                _incomingQueueRead = 0;
            }
            
            Log.Trace("BlockingBidirectionalBuffer: Read complete");
            return bytesToCopy;
        }
    }

    /// <summary>
    /// BLOCKING: Push data to output queue, then wait for it to empty.
    /// This is read by the non-blocking <see cref="ReadNonBlocking"/> method.
    /// </summary>
    public override void Write(byte[] buffer, int offset, int count)
    {
        Log.Trace("Proxy: Write");

        lock (_transferLock)
        {
            if (offset == 0 && count == buffer.Length) _outgoingQueue.AddRange(buffer);
            else _outgoingQueue.AddRange(buffer.Skip(offset).Take(count));
        }

        Log.Trace("Proxy: Write (wait)");
        while (true)
        {
            lock (_transferLock)
            {
                if (_outgoingQueue.Count < 1) break;
            }
            Thread.Sleep(1);
        }

        Log.Trace("Proxy: Write complete");
    }
    
    /// <summary>
    /// Not supported
    /// </summary>
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Not supported
    /// </summary>
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _incomingQueue.Count - _incomingQueueRead;
    
    /// <summary>
    /// Not supported
    /// </summary>
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }
}