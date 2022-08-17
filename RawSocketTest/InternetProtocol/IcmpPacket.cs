using RawSocketTest.Enums;
using RawSocketTest.Helpers;

namespace RawSocketTest.InternetProtocol;

/// <summary>
/// ICMP payload data, from inside an IpPacket.
/// https://en.wikipedia.org/wiki/Ping_(networking_utility)#Message_format
/// </summary>
[ByteLayout]
public class IcmpPacket
{
    /// <summary>
    /// What this message represents
    /// </summary>
    [BigEndian(bytes: 1, order:0)]
    public IcmpType MessageType;
    
    /// <summary>
    /// Sub-codes, dependent on MessageType
    /// </summary>
    [BigEndian(bytes: 1, order:1)]
    public byte MessageCode;
    
    [BigEndian(bytes: 2, order:2)]
    public ushort Checksum;
    
    [BigEndian(bytes: 2, order:3)]
    public ushort PingIdentifier;
    
    [BigEndian(bytes: 2, order:4)]
    public ushort PingSequence;
    
    [RemainingBytes(order: 5)]
    public byte[] Payload = Array.Empty<byte>();
}