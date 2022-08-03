namespace RawSocketTest.Payloads;

/// <summary>
/// Base MessagePayload.
/// Use sub-classes for known types
/// </summary>
public class MessagePayload
{
    /// <summary>
    /// Read, but not stored directly in the payload.
    /// Meaning of the data is dependent on this.
    /// </summary>
    public virtual PayloadType Type { get; set; } = PayloadType.NONE;
    
    /// <summary>
    /// Raw data of payload. Interpretation depends on type.
    /// </summary>
    protected byte[] Data { get; set; } = Array.Empty<byte>();
    
    /// <summary>
    /// Size required to serialise this payload, including data and headers
    /// </summary>
    public int Size => Data.Length + 4;
    
    /// <summary>
    /// Type of next payload in message chain. If 'none', this is
    /// the end of the chain.
    /// </summary>
    public PayloadType NextPayload { get; set; }

    public byte IsCritical { get; set; }
    
    /// <summary>
    /// Total declared length of payload, including data and headers
    /// </summary>
    public ushort Length { get; set; }

    /// <summary>
    /// Serialise to a pre-existing byte array. Returns next offset
    /// </summary>
    public int WriteBytes(byte[] dest, int offset)
    {
        Serialise(); // update Data if needed
        Length = (ushort)Size; // measure size
        
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

    public static MessagePayload Parse(byte[] data, ref int idx, ref PayloadType type)
    {
        var result = new MessagePayload();
        result.ReadData(data, ref idx, ref type);
        return result;
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
        IsCritical = data[idx + 1];
        Length = (UInt16)Bit.Unpack(data, idx + 2, idx + 3); // of the packet, including headers

        // Copy body locally
        var dataLen = Length - 4;
        var remains = data.Length - idx;
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
    protected virtual void Serialise() { }
    
    /// <summary>
    /// Called after copying bytes locally. Sub-classes should fill <see cref="Data"/>
    /// </summary>
    protected virtual void Deserialise() { }
}
