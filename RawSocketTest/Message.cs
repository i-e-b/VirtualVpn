// ReSharper disable BuiltInTypeReferenceStyle

using RawSocketTest.Payloads;

namespace RawSocketTest;

public class IkeMessage
{
    /// <summary>
    /// Sender Security Parameter Indexes.
    /// This must be populated by the entity initially starting the key exchange
    /// <para></para>
    /// RFC 4301: An arbitrary 32-bit value that is used by a receiver to identify the SA to which an incoming packet should be bound
    /// </summary>
    public UInt64 SpiI { get; set; }
    
    /// <summary>
    /// Responder Security Parameter Indexes
    /// <para></para>
    /// This is initially served empty by sender, for the remote side to populate
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
    
    
    public byte[] ToBytes()
    {
        // TODO: crypto, checksums, payloads
        ExpectedLength = PayloadLength + HeaderLength;
        
        FirstPayload = Payloads.Count > 0 ? Payloads[0].Type : PayloadType.NONE;
        
        var bytes = new byte[ExpectedLength];
        WriteHeader(bytes);

        var offset = 28;
        for (int i = 0; i < Payloads.Count; i++)
        {
            // ensure chain is correct
            Payloads[i].NextPayload = (i+1 < Payloads.Count) ? Payloads[i+1].Type : PayloadType.NONE;
            offset = Payloads[i].WriteBytes(bytes, offset);
        }

        return bytes;
    }

    private void WriteHeader(byte[] bytes)
    {
        bytes[0] = Bit.PickByte(8, SpiI);
        bytes[1] = Bit.PickByte(7, SpiI);
        bytes[2] = Bit.PickByte(6, SpiI);
        bytes[3] = Bit.PickByte(5, SpiI);
        bytes[4] = Bit.PickByte(4, SpiI);
        bytes[5] = Bit.PickByte(3, SpiI);
        bytes[6] = Bit.PickByte(2, SpiI);
        bytes[7] = Bit.PickByte(1, SpiI);

        bytes[8] = Bit.PickByte(8, SpiR);
        bytes[9] = Bit.PickByte(7, SpiR);
        bytes[10] = Bit.PickByte(6, SpiR);
        bytes[11] = Bit.PickByte(5, SpiR);
        bytes[12] = Bit.PickByte(4, SpiR);
        bytes[13] = Bit.PickByte(3, SpiR);
        bytes[14] = Bit.PickByte(2, SpiR);
        bytes[15] = Bit.PickByte(1, SpiR);

        bytes[16] = (byte)FirstPayload;
        bytes[17] = (byte)Version;
        bytes[18] = (byte)Exchange;
        bytes[19] = (byte)MessageFlag;

        bytes[20] = Bit.PickByte(4, MessageId);
        bytes[21] = Bit.PickByte(3, MessageId);
        bytes[22] = Bit.PickByte(2, MessageId);
        bytes[23] = Bit.PickByte(1, MessageId);

        bytes[24] = Bit.PickByte(4, ExpectedLength);
        bytes[25] = Bit.PickByte(3, ExpectedLength);
        bytes[26] = Bit.PickByte(2, ExpectedLength);
        bytes[27] = Bit.PickByte(1, ExpectedLength);
    }

    public static IkeMessage FromBytes(byte[] rawData, int offset)
    {
        var result = new IkeMessage
        {
            SpiI = Bit.Unpack(rawData, offset + 0, offset + 7),
            SpiR = Bit.Unpack(rawData, offset + 8, offset + 15),
            FirstPayload = (PayloadType)rawData[offset + 16],
            Version = (IkeVersion)rawData[offset + 17],
            Exchange = (ExchangeType)rawData[offset + 18],
            MessageFlag = (MessageFlag)rawData[offset + 19],
            MessageId = (uint)Bit.Unpack(rawData, offset + 20, offset + 23),
            ExpectedLength = (uint)Bit.Unpack(rawData, offset + 24, offset + 27)
        };
        
        // read payload chain
        int idx = offset + 28;
        var nextPayload = result.FirstPayload;
        while (idx < rawData.Length && nextPayload != PayloadType.NONE)
        {
            var payload = ReadPayload(rawData, ref idx, ref nextPayload);
            result.Payloads.Add(payload);
        }

        return result;
    }

    private static MessagePayload ReadPayload(byte[] rawData, ref int idx, ref PayloadType nextPayload)
    {
        var thisType = nextPayload;
        // TODO: continue to fill out
        switch (thisType)
        {
            case PayloadType.SA:
                return new PayloadSa(rawData, ref idx, ref nextPayload);
            
            case PayloadType.KE:
                return new PayloadKeyExchange(rawData, ref idx, ref nextPayload);
            
            case PayloadType.NONCE:
                return new PayloadNonce(rawData, ref idx, ref nextPayload);
            
            case PayloadType.NOTIFY:
                return new PayloadNotify(rawData, ref idx, ref nextPayload);
            
            case PayloadType.VENDOR:
                return new PayloadVendorId(rawData, ref idx, ref nextPayload);
            
            default: // anything we don't have a parser for yet
            {
                var payload = MessagePayload.Parse(rawData, ref idx, ref nextPayload);
                payload.Type = thisType;
                return payload;
            }
        }
    }
}