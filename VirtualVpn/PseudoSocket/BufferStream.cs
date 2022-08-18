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
    private long _readSequence;
    
    /// <summary>
    /// Sequence number => sub-buffer.
    /// Items are removed as soon as all the data is read.
    /// </summary>
    private readonly Dictionary<long, FragmentBuffer> _buffer = new();


    /// <summary>
    /// Returns true if ANY data is stored.
    /// If the data has been written out of sequence,
    /// it may not be possible to <see cref="Read"/>.
    /// <p></p>
    /// Check <see cref="CanRead"/> to see if in-sequence
    /// data is available 
    /// </summary>
    public bool HasData { get { lock (_lock) { return _buffer.Count > 0; } } }

    /// <summary>
    /// Returns true if data can be read.
    /// Will return false if there is no data
    /// OR the data is beyond the current sequence.
    /// </summary>
    public bool CanRead { get; set; }
    
    /// <summary>
    /// Write data into the buffer
    /// </summary>
    public void Write(long sequence, byte[] data)
    {
        lock (_lock)
        {
            if (_buffer.Count < 1)
            {
                _readSequence = sequence;
            }

            if (_buffer.ContainsKey(sequence))
            {
                Log.Warn($"Received duplicate packet for sequence = {sequence}. Ignoring.");
                return;
            }

            _buffer.Add(sequence, new FragmentBuffer(data));
        }
    }

    /// <summary>
    /// Read available data into a buffer
    /// </summary>
    public long Read(byte[] buffer, int offset, int length)
    {
        throw new Exception("Not yet implemented");
    }
}

/// <summary>
/// Stores the data from one TCP fragment
/// </summary>
internal class FragmentBuffer
{
    public FragmentBuffer(byte[] data)
    {
        throw new NotImplementedException();
    }
}