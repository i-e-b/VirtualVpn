namespace VirtualVpn.TcpProtocol;

internal class SendBuffer
{
    private readonly object _lock = new();
    private readonly Dictionary<long, byte[]> _segments = new();
    public long Start { get; set; }

    public SendBuffer()
    {
        Start = -1;
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
    /// Number of bytes buffered for sending
    /// </summary>
    public long Count()
    {
        lock (_lock)
        {
            return _segments.Sum(s => s.Value.Length);
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

        var empty = Array.Empty<byte>();
        var orderedOffsets = _segments.Keys.OrderBy(k => k).ToList();
        if (orderedOffsets.Count < 1) return empty;

        int i = 0;
        for (; i < orderedOffsets.Count; i++)
        {
            var start = orderedOffsets[i];
            var chunk = _segments[start];
            var end = start + chunk.Length;

            if (start <= offset && end > offset) // found the first chunk in the range
            {
                break;
            }
        }

        if (i >= orderedOffsets.Count) return empty; // can't find any matching data

        var result = new List<byte>(maxSize);
        long remaining = maxSize;
        var loc = offset;
        while (remaining > 0 && i < orderedOffsets.Count)
        {
            var start = orderedOffsets[i];
            if (start > loc) throw new Exception("Gap in transmission stream"); // REALLY shouldn't happen

            var chunkOffset = loc - start;
            var chunk = _segments[start];
            var available = chunk.Length - chunkOffset;

            // check that this is a valid selection (in case of major overlap)
            if (available <= 0)
            {
                i++;
                continue;
            }

            var toTake = remaining < available ? remaining : available;

            result.AddRange(chunk.Skip((int)chunkOffset).Take((int)toTake));
            remaining -= toTake;
            loc += toTake;
            i++;
        }

        return result.ToArray();
    }

    /// <summary>
    /// Release any chunks upto the offset point
    /// </summary>
    public void ConsumeTo(long newStart)
    {
        lock (_lock)
        {
            var offsets = _segments.Keys.ToList();
            foreach (var offset in offsets)
            {
                var end = offset + _segments[offset].Length;
                if (end < newStart) _segments.Remove(offset);
            }

            Start = newStart;
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
            var nextSequence = Start + Count();
            if (offset == 0 && length == buffer.Length)
            {
                _segments.Add(nextSequence, buffer);
            }
            else
            {
                _segments.Add(nextSequence, buffer.Skip(offset).Take(length).ToArray());
            }
        }
    }

    public bool SequenceIsSet() => Start >= 0;

    public void SetStartSequence(uint sndNxt)
    {
        lock (_lock)
        {
            Start = sndNxt;
        }
    }
}