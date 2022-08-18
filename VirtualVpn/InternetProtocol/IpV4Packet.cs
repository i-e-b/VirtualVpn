using System.Diagnostics.CodeAnalysis;
using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.InternetProtocol;

/// <summary>
/// IPv4 packet.
/// https://en.wikipedia.org/wiki/IPv4
/// </summary>
[ByteLayout]
public class IpV4Packet
{
    /// <summary>
    /// The first header field in an IP packet is the four-bit version field. For IPv4, this is always equal to 4.
    /// </summary>
    [BigEndianPartial(bits: 4, order:0)]
    public IpV4Version Version;
    
    /// <summary>
    /// Internet Header Length (IHL).
    /// Should be exactly 5 unless options are added
    /// <p></p>
    /// Length of header, as a count of 32-bit words.
    /// Byte length is this times 4
    /// </summary>
    [BigEndianPartial(bits: 4, order:1)]
    public byte HeaderLength;
    
    /// <summary>
    /// Not used in older TCP.
    /// Can be split between Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN).
    /// <p></p>
    /// Not supported here. See https://en.wikipedia.org/wiki/IPv4#Header
    /// </summary>
    [BigEndian(bytes: 1, order:2)]
    public int ServiceType;
    
    /// <summary>
    /// Defines the entire packet size in bytes, including header and data.
    /// The minimum size is 20 bytes (header without data) and the maximum is 65'535 bytes.
    /// All hosts are required to be able to reassemble datagrams of size up to 576 bytes,
    /// but most modern hosts handle much larger packets.
    /// Links may impose further restrictions on the packet size, in which case datagrams must be fragmented.
    /// Fragmentation in IPv4 is performed in either the sending host or in routers.
    /// Reassembly is performed at the receiving host.
    /// </summary>
    [BigEndian(bytes: 2, order:3)]
    public int TotalLength;
    
    /// <summary>
    /// Identification field.
    /// Primarily used for uniquely identifying the group of fragments of a single IP datagram.
    /// Sometimes co-opted for packet tracing, but RFC 6864 now prohibits any other use.
    /// </summary>
    [BigEndian(bytes: 2, order:4)]
    public int PacketId;
    
    /// <summary>
    /// Fragmentation control flags
    /// </summary>
    [BigEndianPartial(bits: 3, order:5)]
    public IpV4HeaderFlags Flags;
    
    /// <summary>
    /// Specifies the offset of a particular fragment relative to the beginning
    /// of the original un-fragmented IP datagram in units of eight-byte blocks.
    /// <p></p>
    /// The first fragment has an offset of zero.
    /// The 13 bit field allows a maximum offset of 65'528 bytes.
    /// With the header length included = 65'548 bytes.
    /// Supports fragmentation of packets exceeding the maximum IP length of 65,535 bytes.
    /// </summary>
    [BigEndianPartial(bits: 13, order:6)]
    public int FragmentIndex;
    
    /// <summary>
    /// Limits a datagram's lifetime to prevent network failure in the event of a routing loop.
    /// It is specified in seconds, but time intervals less than 1 second are rounded up to 1.
    /// <p></p>
    /// In practice, the field is used as a hop count.
    /// When the datagram arrives at a router, the router decrements the TTL field by one.
    /// When the TTL field reaches zero, the router discards the packet and typically sends an ICMP time exceeded message to the sender.
    /// </summary>
    [BigEndian(bytes: 1, order:7)]
    public int Ttl;
    
    /// <summary>
    /// This field defines the protocol used in the data portion of the IP datagram.
    /// <p></p>
    /// IANA maintains a list of IP protocol numbers as directed by RFC 790.
    /// See https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    /// </summary>
    [BigEndian(bytes: 1, order:8)]
    public IpV4Protocol Protocol;
    
    /// <summary>
    /// The 16-bit IPv4 header checksum field is used for error-checking of the header.
    /// Both UDP and TCP have separate checksums that apply to their data.
    /// <p></p>
    /// For purposes of computing the checksum, the value of the checksum field should be set to zero.
    /// <p></p>
    /// When a packet arrives at a router, the router decreases the TTL field in the header.
    /// Consequently, the router must calculate a new header checksum.
    /// VirtualVPN doesn't decrement the TTL field.
    /// </summary>
    [BigEndian(bytes: 2, order:9)]
    public int Checksum;
    
    /// <summary>
    /// This field is the IPv4 address of the sender of the packet.<br/>
    /// Note: this address may be changed in transit by a network address translation device.
    /// </summary>
    [ByteLayoutChild(order:10)]
    public IpV4Address Source = new();

    /// <summary>
    /// This field is the IPv4 address of the receiver of the packet.<br/>
    /// Note: this address may be changed in transit by a network address translation device.
    /// </summary>
    [ByteLayoutChild(order:11)]
    public IpV4Address Destination = new();
    
    /// <summary>
    /// Optional extra key/value data.
    /// These typically configure a number of behaviors such as for the method to be used during source routing,
    /// some control and probing facilities and a number of experimental features.
    /// <p></p>
    /// The options field is not often used. Packets containing some options may be considered as dangerous by some routers and be blocked.
    /// <p></p>
    /// The value in the HeaderLength field must include enough extra 32-bit words to hold all the options,
    /// plus any padding needed to ensure that the end of the header is aligned to a 32-bit boundary.
    /// </summary>
    [VariableByteString(source: nameof(OptionsLength), order:12)]
    public byte[] Options = Array.Empty<byte>();
    
    /// <summary>
    /// Data carried by this packet. Meaning varies based on <see cref="Protocol"/>.
    /// <p></p>
    /// Note: The packet payload should not be included in the checksum, but often is.
    /// </summary>
    [RemainingBytes(order: 13)]
    public byte[] Payload = Array.Empty<byte>();

    
    /// <summary>
    /// Calculate how many bytes of 'options' we have, based
    /// on length field (usually zero)
    /// </summary>
    public int OptionsLength() => HeaderLength * 4 - 20;

    /// <summary>
    /// Re-write the TCP header-checksum with current values.
    /// This is not affected by payload data, but is affected by payload length.
    /// </summary>
    public void UpdateChecksum()
    {
        // Copy only header data, not payload
        var justHeads = new IpV4Packet
        {
            Version = Version, HeaderLength = HeaderLength, ServiceType = ServiceType,
            TotalLength = TotalLength, PacketId = PacketId, Flags = Flags,
            FragmentIndex = FragmentIndex, Ttl = Ttl, Protocol = Protocol,
            Source = Source, Destination = Destination, Options = Options,
            
            Checksum = 0,
            Payload = Array.Empty<byte>()
        };
        // get bytes
        var headerBytes = ByteSerialiser.ToBytes(justHeads);
        
        // update our checksum
        Checksum = IpChecksum.CalculateChecksum(headerBytes);
    }
}


[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum IpV4Version
{
    Invalid = 0,
    Version4 = 4,
    Version6 = 6
}

[Flags]
[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum IpV4HeaderFlags
{
    None = 0,
    
    /// <summary>
    /// Must not be set
    /// </summary>
    Reserved = 0x04,
    
    /// <summary>
    /// Packet should be dropped if fragmentation would occur.
    /// This can be used when sending packets to a host that does not have resources to perform reassembly of fragments.
    /// </summary>
    DontFragment = 0x02,
    
    /// <summary>
    /// For un-fragmented packets, the MF flag is cleared.
    /// For fragmented packets, all fragments except the last have the MF flag set.
    /// The last fragment has a non-zero Fragment Offset field, differentiating it from an un-fragmented packet.
    /// </summary>
    MoreFragments = 0x01
}

[ByteLayout]
public class IpV4Address
{
    [ByteString(bytes:4, order:0)]
    public byte[] Value = Array.Empty<byte>();

    public string AsString => ToString();
    
    public override string ToString()
    {
        if (Value.Length < 4) return "<empty>";
        return $"{Value[0]}.{Value[1]}.{Value[2]}.{Value[3]}";
    }
}