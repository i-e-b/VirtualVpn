using VirtualVpn.Enums;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TransmissionControlProtocol;

[ByteLayout]
public class TcpSegment
{
    /// <summary>
    /// Identifies the sending port, 0..65535
    /// </summary>
    [BigEndian(bytes:2, order:0)]
    public int SourcePort;
    
    /// <summary>
    /// Identifies the receiving port, 0..65535
    /// </summary>
    [BigEndian(bytes:2, order:1)]
    public int DestinationPort;
    
    /// <summary>
    /// Has a dual role:
    /// <ul>
    /// <li>If the SYN flag is set (1), then this is the initial sequence number.
    ///     The sequence number of the actual first data byte and the acknowledged
    ///     number in the corresponding ACK are then this sequence number plus 1.</li>
    /// 
    /// <li>If the SYN flag is clear (0), then this is the accumulated sequence number
    ///     of the first data byte of this segment for the current session.</li>
    /// </ul>
    /// </summary>
    [BigEndian(bytes:4, order:2)]
    public long SequenceNumber;
    
    /// <summary>
    /// If the ACK flag is set then the value of this field is the next sequence number
    /// that the sender of the ACK is expecting.
    /// <br/>
    /// This acknowledges receipt of all prior bytes (if any).
    /// <para></para>
    /// The first ACK sent by each end acknowledges the other end's
    /// initial sequence number itself, but no data.
    /// </summary>
    [BigEndian(bytes:4, order:3)]
    public long AcknowledgmentNumber;
    
    /// <summary>
    /// Specifies the size of the TCP header in 32-bit words.
    /// <para></para>
    /// The minimum size header is 5 words and the maximum is 15 words thus giving
    /// the minimum size of 20 bytes and maximum of 60 bytes, allowing for up to
    /// 40 bytes of options in the header.
    /// </summary>
    [BigEndianPartial(bits: 4, order:4)]
    public byte DataOffset;
    
    /// <summary>
    /// For future use and should be set to zero
    /// </summary>
    [BigEndianPartial(bits: 3, order:5)]
    public byte Reserved;
    
    /// <summary>
    /// Also known as 'Control Bits'
    /// </summary>
    [BigEndianPartial(bits: 9, order:6)]
    public TcpSegmentFlags Flags;

    /// <summary>
    /// The size of the receive window, which specifies the number of window size units
    /// that the sender of this segment is currently willing to receive.
    /// (See https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Flow_control
    ///  and https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Window_scaling  )
    /// </summary>
    [BigEndian(bytes:2, order:7)]
    public int WindowSize;
    
    /// <summary>
    /// The 16-bit checksum field is used for error-checking of the TCP header, the payload and an IP pseudo-header.
    /// <para></para>
    /// The pseudo-header consists of the source IP address, the destination IP address,
    /// the protocol number for the TCP protocol and the length of the TCP headers and payload (in bytes).
    /// </summary>
    [BigEndian(bytes:2, order:8)]
    public int Checksum;
    
    /// <summary>
    /// If the URG flag is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte.
    /// </summary>
    [BigEndian(bytes:2, order:9)]
    public int UrgentPointer;
    
    /// <summary>
    /// See https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    ///
    /// Options contains any required padding. The padding is composed of zeros
    /// The TCP header padding is used to ensure that the TCP header ends, and data begins, on a 32-bit boundary.
    /// </summary>
    [VariableByteString(source: nameof(OptionsLength), order:10)]
    public byte[] Options = Array.Empty<byte>();
    
    /// <summary>
    /// Segment data. Meaning depends on the application protocol,
    /// which is often determined by port (e.g. 80,443 for HTTP/S)
    /// </summary>
    [RemainingBytes(order: 11)]
    public byte[] Payload = Array.Empty<byte>();
    
    /// <summary>
    /// Calculate how many bytes of 'options' we have, based
    /// on length field (usually zero)
    /// </summary>
    public int OptionsLength() => (DataOffset - 5) * 4;

    /// <summary>
    /// Update the TCP checksum for current headers and payload,
    /// this includes data from the outer wrapper.
    /// <p></p>
    /// https://www.rfc-editor.org/rfc/rfc793#section-3.1
    /// </summary>
    /// <remarks>this is honestly a *weird* checksum</remarks>
    public void UpdateChecksum(byte[] sourceAddress, byte[] destAddress)
    {
        /*
  Checksum:  16 bits

    The checksum field is the 16 bit one's complement of the one's
    complement sum of all 16 bit words in the header and text.  If a
    segment contains an odd number of header and text octets to be
    checksummed, the last octet is padded on the right with zeros to
    form a 16 bit word for checksum purposes.  The pad is not
    transmitted as part of the segment.  While computing the checksum,
    the checksum field itself is replaced with zeros.

    The checksum also covers a 96 bit pseudo header conceptually
    prefixed to the TCP header.  This pseudo header contains the Source
    Address, the Destination Address, the Protocol, and TCP length.
    This gives the TCP protection against misrouted segments.  This
    information is carried in the Internet Protocol and is transferred
    across the TCP/Network interface in the arguments or results of
    calls by the TCP on the IP.

                     +--------+--------+--------+--------+
                     |           Source Address          |
                     +--------+--------+--------+--------+
                     |         Destination Address       |
                     +--------+--------+--------+--------+
                     |  zero  |  PtCl  |    TCP Length   |
                     +--------+--------+--------+--------+

      The TCP Length is the TCP header length plus the data length in
      octets (this is not an explicitly transmitted quantity, but is
      computed), and it does not count the 12 octets of the pseudo
      header.
         */
        // Clear checksum
        Checksum = 0;
        
        // capture message bytes
        var tcpBytes = ByteSerialiser.ToBytes(this);
        
        // calculate and set checksum
        Checksum = IpChecksum.TcpChecksum(sourceAddress, destAddress, 6, tcpBytes.Length, tcpBytes, 0);
    }

    /// <summary>
    /// Update the TCP checksum for current headers and payload,
    /// this includes data from the outer wrapper.
    /// </summary>
    public void UpdateChecksum(IpV4Packet ipv4)
    {
        UpdateChecksum(ipv4.Source.Value, ipv4.Destination.Value);
    }
}