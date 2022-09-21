using System.Diagnostics.CodeAnalysis;

namespace VirtualVpn.TcpProtocol;

/// <summary>
/// TCP protocol "Control" flags.
/// </summary>
[Flags]
[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum TcpSegmentFlags
{
    None = 0,
    
    /// <summary>
    /// Both Syn and Ack flags
    /// </summary>
    SynAck = Syn | Ack,
    
    /// <summary>
    /// Both Fin and Ack flags
    /// </summary>
    FinAck = Fin | Ack,
    
    /// <summary> FIN: Last packet from sender. Assume session is closed after this. </summary>
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
    
    /// <summary>
    /// PSH: Push function.
    /// Asks to push the buffered data to the receiving application.
    /// This is usually used to mark the end of a block of data.
    /// e.g. The end of a http request, or end of a chunk in chunked mode.</summary>
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