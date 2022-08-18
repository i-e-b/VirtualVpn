using System.Diagnostics.CodeAnalysis;
using RawSocketTest.Helpers;

namespace RawSocketTest.TransmissionControlProtocol;

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
}

[Flags]
[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum TcpSegmentFlags
{
    None = 0,
    
    /// <summary> FIN: Last packet from sender </summary>
    Fin = 1 << 0,
    
    /// <summary>
    /// SYN: Synchronize sequence numbers.
    /// <para></para>
    /// Only the first packet sent from each end should have this flag set.
    /// Some other flags and fields change meaning based on this flag,
    /// and some are only valid when it is set, and others when it is clear
    /// </summary>
    Syn = 1 << 1,
    
    /// <summary> RST: Reset the connection </summary>
    Rst = 1 << 2,
    
    /// <summary> PSH: Push function. Asks to push the buffered data to the receiving application </summary>
    Psh = 1 << 3,
    
    /// <summary> ACK: Indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set </summary>
    Ack = 1 << 4,
    
    /// <summary> URG: Indicates that the Urgent pointer field is significant </summary>
    Urg = 1 << 5,
    
    /// <summary>
    /// ECE: ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
    /// <ul>
    /// <li>If the SYN flag is set (1), that the TCP peer is ECN capable.</li>
    /// <li>If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11)
    ///     in the IP header was received during normal transmission.
    ///     This serves as an indication of network congestion (or impending congestion) to the TCP sender.</li>
    /// </ul>
    /// </summary>
    Ece = 1 << 6,
    
    /// <summary>
    /// CWR: Congestion window reduced (CWR) flag is
    /// set by the sending host to indicate that it received a TCP segment with
    /// the ECE flag set and had responded in congestion control mechanism </summary>
    Cwr = 1 << 7,
    
    /// <summary> NS: ECN-nonce - concealment protection </summary>
    Ns_ = 1 << 8,
}