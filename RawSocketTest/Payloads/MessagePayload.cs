using RawSocketTest.Helpers;

namespace RawSocketTest.Payloads;

/// <summary>
/// Base MessagePayload.
/// Use sub-classes for known types
/// </summary>
public abstract class MessagePayload
{
    protected const int HeaderSize = 4; // bytes
    
    /// <summary>
    /// Read, but not stored directly in the payload.
    /// Meaning of the data is dependent on this value.
    /// </summary>
    public virtual PayloadType Type { get; set; } = PayloadType.NONE;
    
    /// <summary>
    /// Raw data of payload. Interpretation depends on type.
    /// </summary>
    public byte[] Data { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Size required to serialise this payload, including data and headers.
    /// This is calculated for serialisation. The declared length from message
    /// data is in <see cref="Length"/>
    /// </summary>
    public abstract int Size { get; }

    /// <summary>
    /// Type of next payload in message chain. If 'none', this is
    /// the end of the chain.
    /// </summary>
    public PayloadType NextPayload { get; set; }

    public byte IsCritical { get; set; }
    
    /// <summary>
    /// Total declared length of payload, including data and headers.
    /// This comes from the incoming data. For the serialisation size, use <see cref="Size"/>
    /// </summary>
    public ushort Length { get; set; }

    /// <summary>
    /// Serialise to a pre-existing byte array. Returns next offset
    /// </summary>
    public int WriteBytes(byte[] dest, int offset)
    {
        var size = Size;
        if (offset + size > dest.Length) throw new Exception($"Target buffer is not long enough for the payload. Require {size}, but have {dest.Length-offset} available");
        
        Serialise(); // update Data if needed
        
        if (Data.Length + HeaderSize != size) throw new Exception($"Internal error: {GetType()} miscalculated serialisation size. Declared {size}, but provided {Data.Length + HeaderSize}");

        Length = (ushort)Size; // measure size to write into header
        
        // write header
        var idx = offset;
        dest[idx++] = (byte)NextPayload;
        dest[idx++] = IsCritical;
        dest[idx++] = (byte)((Length >> 8) & 0xff);
        dest[idx++] = (byte)((Length >> 0) & 0xff);
        
        // write body
        foreach (var dataByte in Data) { dest[idx++] = dataByte; }
        
        return idx;
    }

    /// <summary>
    /// Read payload from a subsection of a byte array.
    /// Updates index and type.
    /// </summary>
    /// <param name="data">Data to parse</param>
    /// <param name="idx">Offset into data to start from</param>
    /// <param name="type">Type of payload</param>
    protected void ReadData(byte[] data, ref int idx, ref PayloadType type)
    {
        // Read header
        Type = type;
        NextPayload = (PayloadType)data[idx + 0];
        IsCritical = (byte)(data[idx + 1] >> 7);
        Length = (UInt16)Bit.Unpack(data, idx + 2, idx + 3); // of the packet, including headers

        // Copy body locally
        var dataLen = Length - 4;
        var remains = data.Length - idx;
        //if (remains < dataLen) throw new Exception($"Message payload data was truncated. Other side declared {dataLen}, but received {remains}. This may be a cryptographic error.");
        if (remains < dataLen) Console.WriteLine($"I have {remains} bytes out of a declared {dataLen}. There may be more packets to come?");
        if (dataLen > 0 && dataLen <= remains)
        {
            Data = new byte[dataLen];
            for (int i = 0; i < dataLen; i++)
            {
                Data[i] = data[idx+4+i];
            }
            Deserialise();
        }

        // Advance to next
        if (Length <= 0)
        {
            idx = data.Length; // don't spin on bad length
        }

        idx += Length;
        type = NextPayload;
    }

    /// <summary>
    /// Called before writing bytes. Sub-classes should fill <see cref="Data"/>
    /// </summary>
    protected abstract void Serialise();
    
    /// <summary>
    /// Called after copying bytes locally. Sub-classes should fill <see cref="Data"/>
    /// </summary>
    protected abstract void Deserialise();
    
    public abstract string Describe();

    /// <summary>
    /// Serialise to a new byte array
    /// </summary>
    public byte[] ToBytes()
    {
        var result = new byte[Size];
        
        WriteBytes(result, 0);
        
        return result;
    }
}
