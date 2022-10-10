namespace VirtualVpn.TcpProtocol;

public class SendBuffer
{
    private readonly object _lock = new();
    private readonly Dictionary<long, byte[]> _segments = new();
    public long Start { get; set; }
    public long ReadHead { get; set; }
    public long End { get; set; }

    public long TotalWritten { get; private set; }

    public SendBuffer()
    {
        Start = -1;
        ReadHead = -1;
        End = -1;
        TotalWritten = 0;
    }

    public byte[] this[long seq]
    {
        get
        {
            lock (_lock)
            {
                return _segments.ContainsKey(seq) ? _segments[seq] : Array.Empty<byte>();
            }
        }
    }

    /// <summary>
    /// Number of bytes buffered for sending, including already sent data
    /// </summary>
    public long Count()
    {
        lock (_lock)
        {
            return _segments.Values.Sum(buf=>buf.Length);
        }
    }

    /// <summary>
    /// Pull data from the buffer, without removing it
    /// </summary>
    public byte[] Pull(long offset, int maxSize)
    {
        lock (_lock)
        {
            return PullInternal(offset, maxSize);
        }
    }

    private byte[] PullInternal(long offset, int maxSize) // lib/col/seqbuf.c:39
    {
        // 1. Walk along the ordered keys until we are inside the offset requested
        // 2. Gather data in chunks until we reach the end of the buffer, or the size requested.
        //    Note: we may have overlap in the offsets we have to account for

        Log.Trace($"SendBuffer:PullInternal - requested offset={offset} up to max of {maxSize} bytes.");
        if (_segments.Count < 1) return Array.Empty<byte>();

        var found = FindFirstSegmentForSequence(offset, out var sequenceStart, out var orderedOffsets);

        if (!found) return Array.Empty<byte>(); // can't find any matching data

        var result = new List<byte>(maxSize);
        long remaining = maxSize;
        var loc = offset;
        while (remaining > 0 && sequenceStart < orderedOffsets.Count)
        {
            var start = orderedOffsets[sequenceStart];
            if (start > loc) throw new Exception("Gap in transmission stream"); // REALLY shouldn't happen

            var chunkOffset = loc - start;
            var chunk = _segments[start];
            var available = chunk.Length - chunkOffset;

            // check that this is a valid selection (in case of major overlap)
            if (available < 0)
            {
                sequenceStart++;
                continue;
            }

            var toTake = remaining < available ? remaining : available;

            var byteSlice = chunk.Skip((int)chunkOffset).Take((int)toTake).ToArray();
            result.AddRange(byteSlice);
            remaining -= byteSlice.Length;
            loc += byteSlice.Length;
            sequenceStart++;
        }

        ReadHead = offset + result.Count;
        Log.Debug($"SendBuffer:Pull - read head moved from {offset} to {ReadHead} ({ReadHead - offset} bytes)");
        return result.ToArray();
    }

    private bool FindFirstSegmentForSequence(long offset, out int offsetsIndex, out List<long> orderedOffsets)
    {
        orderedOffsets = _segments.Keys.OrderBy(k => k).ToList();

        offsetsIndex = 0;
        for (; offsetsIndex < orderedOffsets.Count; offsetsIndex++)
        {
            var start = orderedOffsets[offsetsIndex];
            var chunk = _segments[start];
            var end = start + chunk.Length;

            if (start <= offset && end > offset) // found the first chunk in the range
            {
                break;
            }
        }

        //Log.Debug($"FindFirstSegmentForSequence: offset={offsetsIndex}, count={orderedOffsets.Count}");
        return offsetsIndex < orderedOffsets.Count;
    }

    /// <summary>
    /// Release any chunks upto the offset point
    /// </summary>
    public void ConsumeTo(long newStart)
    {
        lock (_lock)
        {
            if (_segments.Count < 1)
            {
                Log.Debug($"SendBuffer:ConsumeTo - no data to release. Next sequence={newStart}");
                Start = newStart;
                return;
            }

            var offsets = _segments.Keys.ToList();
            foreach (var offset in offsets)
            {
                var end = offset + _segments[offset].Length;
                if (end <= newStart) _segments.Remove(offset);
            }

            Log.Debug($"SendBuffer:ConsumeTo - releasing from {Start} to {newStart} ({newStart - Start} bytes)");
            Start = newStart;
            if (Start > ReadHead) ReadHead = Start;
            if (Start > End) End = Start;
        }
    }

    /// <summary>
    /// Add data to the end of the send buffer
    /// </summary>
    public void Write(byte[] buffer, int offset, int length)
    {
        // should we chop this into MSS chunks, or just feed it directly in?
        lock (_lock)
        {
            if (Start < 0) throw new Exception("Tried to write before setting start sequence");
            if (ReadHead < 0) ReadHead = Start;
            if (End < 0) End = Start + Count();

            var nextSequence = End;

            int written;
            if (offset == 0 && length == buffer.Length)
            {
                _segments.Add(nextSequence, buffer);
                written = buffer.Length;
            }
            else
            {
                var subset = buffer.Skip(offset).Take(length).ToArray();
                _segments.Add(nextSequence, subset);
                written = subset.Length;
            }

            if (written > 0)
            {
                End = nextSequence + written;
            }

            TotalWritten += written;
            Log.Debug($"Wrote to SendBuffer. Buffer start seq={Start}, write start seq={nextSequence}, write end seq={End}; read head={ReadHead}");
        }
    }

    public bool SequenceIsSet() => Start >= 0;

    public void SetStartSequence(uint sndNxt)
    {
        lock (_lock)
        {
            Start = sndNxt;
            ReadHead = sndNxt;
        }
    }

    /// <summary>
    /// Read the available segments and return true
    /// if there is data after the given sequence
    /// </summary>
    public bool HasDataAfter(uint sequence)
    {
        lock (_lock)
        {
            if (_segments.Count < 1) return false;

            return FindFirstSegmentForSequence(sequence, out _, out _);
        }
    }

    public long RemainingData()
    {
        lock (_lock)
        {
            if (_segments.Count < 1) return 0;
            if (End < 0) return 0;
            if (ReadHead < 0) return End - Start;
            return End - ReadHead;
        }
    }
}