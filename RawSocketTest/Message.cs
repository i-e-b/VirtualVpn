// ReSharper disable BuiltInTypeReferenceStyle

namespace RawSocketTest;

public class IkeMessage
{
    /// <summary>
    /// Local Security Parameter Indexes
    /// <para></para>
    /// RFC 4301: An arbitrary 32-bit value that is used by a receiver to identify the SA to which an incoming packet should be bound
    /// </summary>
    public UInt64 SpiI { get; set; }
    
    /// <summary>
    /// Remote Security Parameter Indexes
    /// <para></para>
    /// This is initially served empty, for the remote side to give
    /// </summary>
    public UInt64 SpiR { get; set; }

    /// <summary>
    /// What is the type of the first payload in the message
    /// <para></para>
    /// The types are chained by putting the type of 'next' in each payload
    /// segment. A type of NONE denotes the end
    /// </summary>
    public PayloadType FirstPayload { get; set; }

    /// <summary>
    /// Version of IKE we are using. Should be 0x20 (2.0)
    /// </summary>
    public IkeVersion Version { get; set; }
    
    /// <summary>
    /// What stage of the conversation are we at
    /// </summary>
    public ExchangeType Exchange { get; set; }
    
    /// <summary>
    /// Kind of message. Lack of some flags implies others (e.g. lack of 'Response' means 'Request')
    /// </summary>
    public MessageFlag MessageFlag { get; set; }

    public UInt32 MessageId { get; set; }
    
    /// <summary>
    /// Length of entire packet, including payloads and headers
    /// </summary>
    public UInt32 ExpectedLength { get; set; }
    
    /// <summary>
    /// Length in bytes of all payloads, not including header
    /// </summary>
    public UInt32 PayloadLength => (UInt32)Payloads.Sum(p=>p.Size);

    public List<MessagePayload> Payloads { get; set; } = new();

    /// <summary>
    /// Length in bytes of the 
    /// </summary>
    public const int HeaderLength = 28;
    

    /// <summary>
    /// Add a payload to the payload chain on this message
    /// </summary>
    public void AddPayload(PayloadType type, byte[] message)
    {
        Payloads.Add(new MessagePayload{
            Data = message,
            Type = type
        });
    }
    
    public byte[] ToBytes()
    {
        // TODO: crypto, checksums, payloads
        ExpectedLength = PayloadLength + HeaderLength;
        
        var bytes = new byte[ExpectedLength];
        
        // Write header
        bytes[0] = PickByte(8, SpiI);
        bytes[1] = PickByte(7, SpiI);
        bytes[2] = PickByte(6, SpiI);
        bytes[3] = PickByte(5, SpiI);
        bytes[4] = PickByte(4, SpiI);
        bytes[5] = PickByte(3, SpiI);
        bytes[6] = PickByte(2, SpiI);
        bytes[7] = PickByte(1, SpiI);
        
        bytes[ 8] = PickByte(8, SpiR);
        bytes[ 9] = PickByte(7, SpiR);
        bytes[10] = PickByte(6, SpiR);
        bytes[11] = PickByte(5, SpiR);
        bytes[12] = PickByte(4, SpiR);
        bytes[13] = PickByte(3, SpiR);
        bytes[14] = PickByte(2, SpiR);
        bytes[15] = PickByte(1, SpiR);
        
        bytes[16] = (byte)FirstPayload;
        bytes[17] = (byte)Version;
        bytes[18] = (byte)Exchange;
        bytes[19] = (byte)MessageFlag;
        
        bytes[20] = PickByte(4, MessageId);
        bytes[21] = PickByte(3, MessageId);
        bytes[22] = PickByte(2, MessageId);
        bytes[23] = PickByte(1, MessageId);
        
        bytes[24] = PickByte(4, ExpectedLength);
        bytes[25] = PickByte(3, ExpectedLength);
        bytes[26] = PickByte(2, ExpectedLength);
        bytes[27] = PickByte(1, ExpectedLength);
        
        return bytes;
    }

    public static IkeMessage FromBytes(byte[] rawData)
    {
        var result = new IkeMessage
        {
            SpiI = Unpack(rawData, 0, 7),
            SpiR = Unpack(rawData, 8, 15),
            FirstPayload = (PayloadType)rawData[16],
            Version = (IkeVersion)rawData[17],
            Exchange = (ExchangeType)rawData[18],
            MessageFlag = (MessageFlag)rawData[19],
            MessageId = (uint)Unpack(rawData, 20,23),
            ExpectedLength = (uint)Unpack(rawData, 24,27)
        };
        
        // read payload chain
        int idx = 28;
        var nextPayload = result.FirstPayload;
        while (idx < rawData.Length && nextPayload != PayloadType.NONE)
        {
            result.ParsePayload(rawData, ref idx, ref nextPayload);
        }

        return result;
    }

    private void ParsePayload(byte[] data, ref int idx, ref PayloadType type)
    {
        // Read header
        var result = new MessagePayload
        {
            Type = type,
            NextPayload = (PayloadType)data[idx+0],
            IsCritical = data[idx+1],
            Length = (UInt16)Unpack(data, idx+2, idx+3) // of the packet, including headers
        };

        // Read body
        var dataLen = result.Length - 4;
        var remains = data.Length - idx;
        if (dataLen > 0 && dataLen <= remains)
        {
            result.Data = new byte[dataLen];
            for (int i = 0; i < dataLen; i++)
            {
                result.Data[i] = data[idx+4+i];
            }
        }
        
        // Add to list
        Payloads.Add(result);

        // Advance to next
        if (result.Length <= 0)
        {
            idx = data.Length; // don't spin on bad length
        }

        idx += result.Length;
        type = result.NextPayload;
    }


    /// <summary>
    /// Read a byte from a larger integer
    /// </summary>
    private static byte PickByte(int byteIndex, ulong data)
    {
        var s = 8 * (byteIndex - 1);
        return (byte)((data >> s) & 0xff);
    }

    /// <summary>
    /// Read bytes from start to end (inclusive) into long, in network order
    /// </summary>
    private static UInt64 Unpack(byte[] source, int startIdx, int endIdx)
    {
        var result = 0UL;

        for (var i = startIdx; i <= endIdx; i++)
        {
            result <<= 8;
            result |= source[i];
        }
        
        return result;
    }
}

public class MessagePayload
{
    /// <summary>
    /// Read, but not stored directly in the payload.
    /// Meaning of the data is dependent on this.
    /// </summary>
    public PayloadType Type { get; set; } = PayloadType.NONE;
    
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public int Size { get; set; }
    
    /// <summary>
    /// Type of next payload in message chain. If 'none', this is
    /// the end of the chain.
    /// </summary>
    public PayloadType NextPayload { get; set; }

    public byte IsCritical { get; set; }
    
    /// <summary>
    /// Total length of payload, including data and headers
    /// </summary>
    public ushort Length { get; set; }
}
