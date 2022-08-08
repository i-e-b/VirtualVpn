// ReSharper disable BuiltInTypeReferenceStyle

using RawSocketTest.Crypto;
using RawSocketTest.Payloads;
using SkinnyJson;

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
    /// Length in bytes of the IKE message header
    /// </summary>
    public const int HeaderLength = 28;
    
    
    public int DataOffset { get; private set; }
    
    /// <summary>
    /// Original data supplied across network.
    /// Empty if message is generated locally.
    /// The values here should never be updated once the message is received.
    /// </summary>
    private byte[] RawData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Serialise the message to a byte string
    /// </summary>
    /// <param name="sendZeroHeader">If true, 4 bytes of zero will be prepended to the data</param>
    /// <param name="ikeCrypto"></param>
    public byte[] ToBytes(bool sendZeroHeader = false, IkeCrypto? ikeCrypto = null)
    {
        // TODO: crypto, checksums
        
        ExpectedLength = PayloadLength + HeaderLength;
        var offset = 0;
        if (sendZeroHeader)
        {
            offset = 4;
            ExpectedLength += 4;
        }

        FirstPayload = Payloads.Count > 0 ? Payloads[0].Type : PayloadType.NONE;

        if (ikeCrypto is not null)
        {
            // TODO: implement. See pvpn/message.py:555
            throw new Exception("Building crypto packets isn't implemented yet");
        }

        var bytes = new byte[ExpectedLength];
        WriteHeader(bytes, offset);

        offset += 28;
        for (int i = 0; i < Payloads.Count; i++)
        {
            // ensure chain is correct
            Payloads[i].NextPayload = (i+1 < Payloads.Count) ? Payloads[i+1].Type : PayloadType.NONE;
            offset = Payloads[i].WriteBytes(bytes, offset);
        }


        if (ikeCrypto is not null)
        {
            // TODO: write checksum
        }

        if (offset != ExpectedLength) throw new Exception($"Unexpected write length. Expected {ExpectedLength}, but got {offset}");

        return bytes;
    }

    private void WriteHeader(byte[] bytes, int offset)
    {
        bytes[offset+0] = Bit.PickByte(8, SpiI);
        bytes[offset+1] = Bit.PickByte(7, SpiI);
        bytes[offset+2] = Bit.PickByte(6, SpiI);
        bytes[offset+3] = Bit.PickByte(5, SpiI);
        bytes[offset+4] = Bit.PickByte(4, SpiI);
        bytes[offset+5] = Bit.PickByte(3, SpiI);
        bytes[offset+6] = Bit.PickByte(2, SpiI);
        bytes[offset+7] = Bit.PickByte(1, SpiI);

        bytes[offset+8] = Bit.PickByte(8, SpiR);
        bytes[offset+9] = Bit.PickByte(7, SpiR);
        bytes[offset+10] = Bit.PickByte(6, SpiR);
        bytes[offset+11] = Bit.PickByte(5, SpiR);
        bytes[offset+12] = Bit.PickByte(4, SpiR);
        bytes[offset+13] = Bit.PickByte(3, SpiR);
        bytes[offset+14] = Bit.PickByte(2, SpiR);
        bytes[offset+15] = Bit.PickByte(1, SpiR);

        bytes[offset+16] = (byte)FirstPayload;
        bytes[offset+17] = (byte)Version;
        bytes[offset+18] = (byte)Exchange;
        bytes[offset+19] = (byte)MessageFlag;

        bytes[offset+20] = Bit.PickByte(4, MessageId);
        bytes[offset+21] = Bit.PickByte(3, MessageId);
        bytes[offset+22] = Bit.PickByte(2, MessageId);
        bytes[offset+23] = Bit.PickByte(1, MessageId);

        bytes[offset+24] = Bit.PickByte(4, ExpectedLength);
        bytes[offset+25] = Bit.PickByte(3, ExpectedLength);
        bytes[offset+26] = Bit.PickByte(2, ExpectedLength);
        bytes[offset+27] = Bit.PickByte(1, ExpectedLength);
    }

    public static IkeMessage FromBytes(byte[] rawData, int offset)
    {
        var result = new IkeMessage
        {
            RawData = rawData,
            DataOffset = offset,
            
            SpiI = Bit.Unpack(rawData, offset + 0, offset + 7),
            SpiR = Bit.Unpack(rawData, offset + 8, offset + 15),
            FirstPayload = (PayloadType)rawData[offset + 16],
            Version = (IkeVersion)rawData[offset + 17],
            Exchange = (ExchangeType)rawData[offset + 18],
            MessageFlag = (MessageFlag)rawData[offset + 19],
            MessageId = (uint)Bit.Unpack(rawData, offset + 20, offset + 23),
            ExpectedLength = (uint)Bit.Unpack(rawData, offset + 24, offset + 27)
        };
        
        // The payload reading should be deferred until crypto is known (agreed or not encrypted).
        // See `ReadPayloads()`

        return result;
    }


    public void ReadPayloadChain(IkeCrypto? encryption)
    {
        var offset = DataOffset; // where in the data bytes does the actual message start?
        var srcData = RawData;
        
        // Decrypt message if needed. See pvpn/message.py:525
        // NOTE: this is whole-message encryption. SK payload encryption is separate, and handled in `ReadSinglePayload` below.
        if (MessageFlag.HasFlag(MessageFlag.Encryption))
        {
            if (encryption is null) throw new Exception("Message is flagged as encrypted, but no crypto was supplied");
            
            
            // make sure we have just the target data
            if (offset != 0) srcData = srcData.Skip(offset).ToArray();
            
            // decrypt data and reset offset
            srcData = encryption.Decrypt1(srcData, MessageId);
            offset = 0;
        }

        // read payload chain
        var idx = offset+28;
        var payloads = ReadPayloadChainInternal(FirstPayload, encryption, ref idx, srcData);

        Payloads.AddRange(payloads);
    }

    private static IEnumerable<MessagePayload> ReadPayloadChainInternal(PayloadType first, IkeCrypto? encryption, ref int idx, byte[] srcData)
    {
        var payloads = new List<MessagePayload>();
        var nextPayload = first;
        while (idx < srcData.Length && nextPayload != PayloadType.NONE)
        {
            var payload = ReadSinglePayload(srcData, encryption, ref idx, ref nextPayload);
            payloads.AddRange(payload);
        }

        return payloads;
    }

    /// <summary>
    /// Read one payload's bytes, and interpret into the appropriate class types.
    /// The SK payload contains potentially many child payloads, so we return enumerable
    /// </summary>
    public static IEnumerable<MessagePayload> ReadSinglePayload(byte[] srcData, IkeCrypto? ikeCrypto, ref int idx, ref PayloadType nextPayload)
    {
        var thisType = nextPayload;
        // TODO: continue to fill out
        switch (thisType)
        {
            case PayloadType.SA:
                return One(new PayloadSa(srcData, ref idx, ref nextPayload));
            
            case PayloadType.KE:
                return One(new PayloadKeyExchange(srcData, ref idx, ref nextPayload));
            
            case PayloadType.NONCE:
                return One(new PayloadNonce(srcData, ref idx, ref nextPayload));
            
            case PayloadType.NOTIFY:
                return One(new PayloadNotify(srcData, ref idx, ref nextPayload));
            
            case PayloadType.VENDOR:
                return One(new PayloadVendorId(srcData, ref idx, ref nextPayload));

            case PayloadType.SK: // encrypted body. TODO: This should be pumped back around to read contents?
            {
                if (ikeCrypto is null) throw new Exception("Received an encrypted packet without agreeing on session crypto");
                var ok = ikeCrypto.VerifyChecksum(srcData); // IEB: currently failing?
                if (!ok) Console.WriteLine("CHECKSUM FAILED! We will continue, but result might be unreliable");
                
                var expandedPayload = new PayloadSecured(srcData, ikeCrypto, ref idx, ref nextPayload);
                // TODO: read the 'plain' as a new set of payloads
                
                Console.WriteLine($"    Plain body has {expandedPayload.PlainBody?.Length.ToString() ?? "no"} bytes");
                if (expandedPayload.PlainBody?.Length > 0)
                {
                    Console.WriteLine($"    Reading inner payload, starting with {nextPayload.ToString()}");
    
                    var childIdx = 0;
                    var innerPayloads = ReadPayloadChainInternal(nextPayload, ikeCrypto, ref childIdx, expandedPayload.PlainBody).ToList();
                    
                    Console.WriteLine($"    Got {innerPayloads.Count} inner payloads:\r\n{Json.Beautify(Json.Freeze(innerPayloads))}");
                    
                    return innerPayloads;
                }

                return Array.Empty<MessagePayload>();
            }
            default: // anything we don't have a parser for yet
            {
                var payload = new PayloadUnknown(srcData, ref idx, ref nextPayload) { Type = thisType };
                return One(payload);
            }
        }
    }

    private static IEnumerable<T> One<T>(T thing) { yield return thing; }

    /// <summary>
    /// Get the first payload of a given type, that matches the predicate
    /// </summary>
    public T? GetPayload<T>(Func<T,bool>? pred = null)
    {   
        if (pred is null) return Payloads.OfType<T>().FirstOrDefault();
        return Payloads.OfType<T>().FirstOrDefault(pred);
    }
}