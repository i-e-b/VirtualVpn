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
    /// Length in bytes of the full message (including headers)
    /// </summary>
    public UInt32 PayloadLength { get; set; }

    /// <summary>
    /// Length in bytes of the 
    /// </summary>
    public const int HeaderLength = 28;
    
    public byte[] ToBytes()
    {
        // TODO: crypto, checksums, payloads
        var packetLength = PayloadLength + HeaderLength;
        
        var bytes = new byte[packetLength];
        
        // Write header
        bytes[0] = B(8, SpiI);
        bytes[1] = B(7, SpiI);
        bytes[2] = B(6, SpiI);
        bytes[3] = B(5, SpiI);
        bytes[4] = B(4, SpiI);
        bytes[5] = B(3, SpiI);
        bytes[6] = B(2, SpiI);
        bytes[7] = B(1, SpiI);
        
        bytes[ 8] = B(8, SpiR);
        bytes[ 9] = B(7, SpiR);
        bytes[10] = B(6, SpiR);
        bytes[11] = B(5, SpiR);
        bytes[12] = B(4, SpiR);
        bytes[13] = B(3, SpiR);
        bytes[14] = B(2, SpiR);
        bytes[15] = B(1, SpiR);
        
        bytes[16] = (byte)FirstPayload;
        bytes[17] = (byte)Version;
        bytes[18] = (byte)Exchange;
        bytes[19] = (byte)MessageFlag;
        
        bytes[20] = B(4, MessageId);
        bytes[21] = B(3, MessageId);
        bytes[22] = B(2, MessageId);
        bytes[23] = B(1, MessageId);
        
        bytes[24] = B(4, packetLength);
        bytes[25] = B(3, packetLength);
        bytes[26] = B(2, packetLength);
        bytes[27] = B(1, packetLength);
        
        return bytes;
    }

    private byte B(int byteIndex, ulong data)
    {
        var s = 8 * (byteIndex - 1);
        return (byte)((data >> s) & 0xff);
    }
}
