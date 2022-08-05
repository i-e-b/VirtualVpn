﻿// ReSharper disable BuiltInTypeReferenceStyle

using RawSocketTest.Crypto;
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
    
    
    public int DataOffset { get; private set; }
    public byte[] RawData { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Serialise the message to a byte string
    /// </summary>
    /// <param name="sendZeroHeader">If true, 4 bytes of zero will be prepended to the data</param>
    /// <param name="ikeCrypto"></param>
    public byte[] ToBytes(bool sendZeroHeader = false, IkeCrypto? ikeCrypto = null)
    {
        // TODO: crypto, checksums, payloads
        
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


    public void ReadPayloads(IkeCrypto? encryption)
    {
        var offset = DataOffset; // where in the data bytes does the actual message start?
        var srcData = RawData;
        
        // Decrypt message if needed. See pvpn/message.py:525
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
        int idx = offset + 28;
        var nextPayload = FirstPayload;
        while (idx < srcData.Length && nextPayload != PayloadType.NONE)
        {
            var payload = ReadPayload(srcData, encryption, ref idx, ref nextPayload);
            Payloads.Add(payload);
        }
    }

    private static MessagePayload ReadPayload(byte[] rawData, IkeCrypto? ikeCrypto, ref int idx, ref PayloadType nextPayload)
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
            
            case PayloadType.SK: // encrypted body. TODO: This should be pumped back around to read contents?
                return new PayloadSecured(rawData, ikeCrypto, ref idx, ref nextPayload);
            
            default: // anything we don't have a parser for yet
            {
                var payload = MessagePayload.Parse(rawData, ref idx, ref nextPayload);
                payload.Type = thisType;
                return payload;
            }
        }
    }

    /// <summary>
    /// Get the first payload of a given type, that matches the predicate
    /// </summary>
    public T? GetPayload<T>(Func<T,bool>? pred = null)
    {   
        if (pred is null) return Payloads.OfType<T>().FirstOrDefault();
        return Payloads.OfType<T>().FirstOrDefault(pred);
    }
}