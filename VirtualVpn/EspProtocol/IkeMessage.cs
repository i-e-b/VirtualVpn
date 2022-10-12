// ReSharper disable BuiltInTypeReferenceStyle

using System.Diagnostics.CodeAnalysis;
using VirtualVpn.Crypto;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol.Payloads;
using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol;

[SuppressMessage("ReSharper", "PropertyCanBeMadeInitOnly.Global")]
[SuppressMessage("ReSharper", "PropertyCanBeMadeInitOnly.Local")]
public class IkeMessage
{
    /// <summary>
    /// Sender Security Parameter Indexes.
    /// This must be populated by the entity initially starting the key exchange
    /// <para></para>
    /// RFC 4301: An arbitrary 32-bit value that is used by a receiver to identify the SA to which an incoming packet should be bound;
    /// RFC 5723: "octet SPIi[8], SPIr[8];"
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
    public byte[] RawData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Serialise the message to a byte string
    /// </summary>
    /// <param name="sendZeroHeader">If true, 4 bytes of zero will be prepended to the data</param>
    /// <param name="ikeCrypto"></param>
    public byte[] ToBytes(bool sendZeroHeader = false, IkeCrypto? ikeCrypto = null)
    {
        var idx = 0;

        FirstPayload = Payloads.Count > 0 ? Payloads[0].Type : PayloadType.NONE;
        
        var payloadData = EncodePayloads();

        if (ikeCrypto is not null)
        {
            // pvpn/message.py:555
            var rawEncrypted = ikeCrypto.Encrypt(payloadData);
            var sk = new PayloadSecured(rawEncrypted)
            {
                NextPayload = FirstPayload
            };
            payloadData = sk.ToBytes();
            
            FirstPayload = PayloadType.SK;
        }
        
        ExpectedLength = (uint)(payloadData.Length + HeaderLength);

        var bytes = new byte[ExpectedLength];
        WriteHeader(bytes, ref idx);
        Bit.CopyOver(src: payloadData, dst: bytes, ref idx);

        if (ikeCrypto?.Integrity is not null)
        {
            // pvpn/message.py:571
            Log.Trace("Using standard checksum");
            ikeCrypto.AddChecksum(bytes, Array.Empty<byte>());
        }

        if (idx != ExpectedLength) throw new Exception($"Unexpected write length. Expected {ExpectedLength}, but got {idx}");
        
        return sendZeroHeader ? new byte[4].Concat(bytes).ToArray() : bytes;
    }

    private byte[] EncodePayloads()
    {
        var result = new byte[PayloadLength];
        var idx = 0;
        for (int i = 0; i < Payloads.Count; i++)
        {
            // ensure chain is correct
            Payloads[i].NextPayload = (i + 1 < Payloads.Count) ? Payloads[i + 1].Type : PayloadType.NONE;
            idx = Payloads[i].WriteBytes(result, idx);
        }

        if (idx != result.Length)
        {
            Log.Warn($"    WARNING: EncodePayloads unexpected length. Expected {result.Length}, but got {idx}.");
        }

        return result;
    }

    private void WriteHeader(byte[] bytes, ref int offset)
    {
        Bit.WriteUInt64(SpiI, bytes, ref offset);
        Bit.WriteUInt64(SpiR, bytes, ref offset);

        bytes[offset++] = (byte)FirstPayload;
        bytes[offset++] = (byte)Version;
        bytes[offset++] = (byte)Exchange;
        bytes[offset++] = (byte)MessageFlag;

        Bit.WriteUInt32(MessageId, bytes, ref offset);
        Bit.WriteUInt32(ExpectedLength, bytes, ref offset);
    }

    public static IkeMessage FromBytes(byte[] rawData, int offset)
    {
        if ((rawData.Length-offset) < 28) throw new Exception($"Invalid data length. Expected at least 28 bytes, got {rawData.Length} with offset {offset}");
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
            Log.Debug("    Message is fully encrypted");
            
            // make sure we have just the target data
            if (offset != 0) srcData = srcData.Skip(offset).ToArray();
            
            // decrypt data and reset offset
            srcData = encryption.Decrypt1(srcData, MessageId);
            offset = 0;
        }

        // read payload chain
        var idx = offset+28;
        var payloads = ReadPayloadChainInternal(FirstPayload, encryption, ref idx, srcData, RawData);

        Payloads.AddRange(payloads);
    }

    private static IEnumerable<MessagePayload> ReadPayloadChainInternal(PayloadType first, IkeCrypto? encryption, ref int idx, byte[] srcData, byte[]? rawData)
    {
        var payloads = new List<MessagePayload>();
        var nextPayload = first;
        Log.Debug($"    Reading chain: {srcData.Length} bytes starting at {idx} (from raw data of {rawData?.Length.ToString() ?? "n/a"})");

        if (idx >= srcData.Length)
        {
            Log.Warn("    WARNING: start index was already at end of data");
            return payloads;
        }

        while (idx < srcData.Length && nextPayload != PayloadType.NONE)
        {
            var payload = ReadSinglePayload(srcData, encryption, ref idx, ref nextPayload, rawData);
            Log.Debug($"        Next payload: {nextPayload.ToString()}, ended at {idx}");
            payloads.AddRange(payload);
        }

        if (nextPayload != PayloadType.NONE)
        {
            Log.Warn("    WARNING: got to the end of payload data without finding a PayloadType.NONE");
        }

        if (idx != srcData.Length)
        {
            Log.Warn($"    WARNING: got to the end of payload data without reaching data end (ended at {idx}, length={srcData.Length})");
        }

        return payloads;
    }

    /// <summary>
    /// Read one payload's bytes, and interpret into the appropriate class types.
    /// The SK payload contains potentially many child payloads, so we return enumerable
    /// </summary>
    public static IEnumerable<MessagePayload> ReadSinglePayload(byte[] srcData, IkeCrypto? ikeCrypto, ref int idx, ref PayloadType nextPayload, byte[]? rawData = null)
    {
        Log.Debug($"    Reading payload {nextPayload.ToString()} from source ({srcData.Length} bytes starting at {idx})");
        var thisType = nextPayload;
        
        // This is not exhaustive, but has everything I've needed so far.
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
            
            case PayloadType.IDi:
                return One(new PayloadIDi(srcData, ref idx, ref nextPayload));
            
            case PayloadType.IDr:
                return One(new PayloadIDr(srcData, ref idx, ref nextPayload));
            
            case PayloadType.TSi:
                return One(new PayloadTsi(srcData, ref idx, ref nextPayload));
            
            case PayloadType.TSr:
                return One(new PayloadTsr(srcData, ref idx, ref nextPayload));
            
            case PayloadType.AUTH:
                return One(new PayloadAuth(srcData, ref idx, ref nextPayload));

            case PayloadType.SKF:{
                Log.Critical("FOUND AN SKF PAYLOAD! #################");
                return Array.Empty<MessagePayload>();
            }

            case PayloadType.DELETE:
                return One(new PayloadDelete(srcData, ref idx, ref nextPayload));

            case PayloadType.SK: // encrypted body. This needs to be sent back around to read contents.
            {
                // https://www.rfc-editor.org/rfc/rfc7296#section-3
                if (ikeCrypto is null)
                {
                    throw new BadSessionException("Received an encrypted packet without agreeing on session crypto");
                }

                //if (rawData is not null) File.WriteAllBytes(Settings.FileBase + "SK-raw.bin", rawData); // log the entire message
                
                var ok = ikeCrypto.VerifyChecksum(srcData);
                if (!ok) Log.Warn("CHECKSUM FAILED! We will continue, but result might be unreliable (in VirtualVpn.IkeMessage.ReadSinglePayload)");
                else Log.Debug("Checksum passed in VirtualVpn.IkeMessage.ReadSinglePayload");
                
                // SK must be last, as it's 'next payload' field is actually the first of the encrypted contents
                var expandedPayload = new PayloadSecured(srcData, ikeCrypto, ref idx, ref nextPayload);
                // read the 'plain' as a new set of payloads
                
                Log.Debug($"    Plain body has {expandedPayload.PlainBody?.Length.ToString() ?? "no"} bytes");
                if (expandedPayload.PlainBody?.Length > 0)
                {
                    Log.Debug($"    Reading inner payload, starting with {nextPayload.ToString()}");

                    var childIdx = 0;
                    var innerPayloads = ReadPayloadChainInternal(nextPayload, ikeCrypto, ref childIdx, expandedPayload.PlainBody, rawData).ToList();
                    
                    Log.Debug($"    Got {innerPayloads.Count} inner payloads:\r\n{string.Join("\r\n",innerPayloads.Select(p=>p.Describe()))}");
                    
                    nextPayload = PayloadType.NONE; // end of internal run
                    return innerPayloads;
                }

                return Array.Empty<MessagePayload>();
            }
            default: // anything we don't have a parser for yet
            {
                Log.Trace($"Payload type not handled: {thisType.ToString()} ({(int)thisType})");
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

    public IEnumerable<string> DescribeAllPayloads() => Payloads.Select(payload => payload.Describe());
}

public class BadSessionException : Exception
{
    public BadSessionException(string message):base(message) { }
}