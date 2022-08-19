namespace VirtualVpn.PseudoSocket;

/// <summary>
/// A continuous read/write buffer,
/// with support for out-of-order writes.
/// </summary>
public class BufferStream
{
    private readonly object _lock = new();

    /// <summary>
    /// The sequence number the read-head is on
    /// </summary>
    private long? _readSequence;
    
    /// <summary>
    /// If the remote side claimed that transmission is complete,
    /// we store the end sequence number here.
    /// </summary>
    private long? _endSequence;
    
    /// <summary>
    /// Sequence number => sub-buffer.
    /// Items are removed as soon as all the data is read.
    /// </summary>
    private readonly Dictionary<long, FragmentBuffer> _fragments = new();

    /// <summary>
    /// Returns true if ANY data is stored.
    /// If the data has been written out of sequence,
    /// it may not be possible to <see cref="Read"/>.
    /// <p></p>
    /// Check <see cref="CanRead"/> to see if in-sequence
    /// data is available 
    /// </summary>
    public bool HasData { get { lock (_lock) { return _fragments.Count > 0; } } }

    /// <summary>
    /// Returns true if data can be read.
    /// Will return false if there is no data
    /// OR the data is beyond the current sequence.
    /// </summary>
    public bool CanRead { get { lock (_lock) { return _fragments.Count > 0 && (_readSequence is null || _fragments.ContainsKey(_readSequence.Value)); } } }

    /// <summary>
    /// True if the sender has declared an end to the stream
    /// </summary>
    public bool Complete => _endSequence is not null;
    
    /// <summary>
    /// True if all available data has been read
    /// up to the limit declared by the sender.
    /// </summary>
    public bool AllDataRead => _readSequence > _endSequence && _fragments.Count < 1;

    /// <summary>
    /// Lowest sequence seen in the feed so far, or zero if no data
    /// </summary>
    public long StartSequence { get; private set; }

    /// <summary>
    /// Return true if all stored fragments have no gaps
    /// </summary>
    public bool SequenceComplete {
        get {
            if (_fragments.Count < 1) return false;
            var min = StartSequence;
            var end = min + _fragments.Count;
            for (var i = min; i < end; i++)
            {
                if ( ! _fragments.ContainsKey(i)) return false;
            }
            return true;
        }
    }

    public string Keys => string.Join(", ", _fragments.Keys);

    /// <summary>
    /// Write data into the buffer
    /// </summary>
    public void Write(long sequence, byte[] data)
    {
        if (data.Length < 1) return;
        lock (_lock)
        {
            if (_fragments.Count < 1)
            {
                _endSequence = null;
                StartSequence = sequence;
            }
            else
            {
                StartSequence = StartSequence < sequence ? StartSequence : sequence;
            }

            if (_fragments.ContainsKey(sequence))
            {
                Log.Warn($"Received duplicate packet for sequence = {sequence}. Ignoring.");
                return;
            }

            _fragments.Add(sequence, new FragmentBuffer(data));
        }
    }

    /// <summary>
    /// Flags the buffer as complete, until the next fragment is written.
    /// </summary>
    public void SetComplete(long endSequence)
    {
        _endSequence = endSequence;
    }

    /// <summary>
    /// Read available data into a buffer.
    /// Returns actual bytes read.
    /// </summary>
    /// <param name="buffer">buffer to read into</param>
    /// <param name="offset">offset into buffer to start</param>
    /// <param name="length">maximum number of bytes to read</param>
    public int Read(byte[] buffer, int offset, int length)
    {
        if (offset >= buffer.Length) throw new Exception("Tried to write outside of buffer");
        if (offset < 0) throw new Exception("Negative offset not allowed");
        if (length <= 0) return 0;
        
        lock (_lock)
        {
            if (_fragments.Count < 1) return 0; // nothing to read
            _readSequence ??= StartSequence;
            if (!_fragments.ContainsKey(_readSequence.Value)) return 0; // next fragment isn't available yet
            
            // how many bytes could we fill?
            var available = buffer.Length - offset;
            var remains = available > length ? length : available;
            
            // Until we fill 'length', or run out of data, keep pulling slices
            var total = 0;
            var idx = offset;
            while (remains > 0)
            {
                if (_fragments.Count < 1) break; // ran out of data
                if ( ! _fragments.ContainsKey(_readSequence!.Value)) break; // hit a fragment gap
                
                var frag = _fragments[_readSequence.Value];
                total += frag.Read(buffer, ref remains, ref idx);

                if (frag.IsDone)
                {
                    _fragments.Remove(_readSequence.Value);
                    _readSequence++;
                }
            }
            
            return total;
        }
    }

    /// <summary>
    /// Read all fragments in order
    /// </summary>
    public IList<ArraySegment<byte>> AllBuffers()
    {
        var list = new List<ArraySegment<byte>>();
        var keys = _fragments.Keys.OrderBy(k => k);
        foreach (var key in keys)
        {
            list.Add(_fragments[key].Raw);
        }
        return list;
    }
}

/// <summary>
/// Stores the data from one TCP fragment
/// </summary>
internal class FragmentBuffer
{
    private int _offset;
    private readonly byte[] _data;

    public FragmentBuffer(byte[] data)
    {
        _offset = 0;
        _data = data;
    }

    public bool IsDone => _offset >= _data.Length;
    public ArraySegment<byte> Raw => _data;

    /// <summary>
    /// Read into a buffer
    /// </summary>
    /// <param name="buffer">target</param>
    /// <param name="max">max number of bytes to copy. Reduced by amount copied</param>
    /// <param name="idx">start offset, updated to end offset</param>
    /// <returns>total bytes written</returns>
    public int Read(byte[] buffer, ref int max, ref int idx)
    {
        var available = _data.Length - _offset;
        var copy = available > max ? max : available;
        for (int i = 0; i < copy; i++)
        {
            max--;
            buffer[idx++] = _data[_offset++];
        }
        return copy;
    }
}