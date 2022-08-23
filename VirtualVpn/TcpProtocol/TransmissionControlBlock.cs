// ReSharper disable BuiltInTypeReferenceStyle
// ReSharper disable UnusedMember.Global
namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Transmission Control Block (TCB)
/// is the standard state machine used to drive TCP/IP sessions.
/// </summary>
public class TransmissionControlBlock
{
    /// <summary>
    /// initial receive sequence number
    /// </summary>
    public UInt32 Irs { get; set; }

    /// <summary>
    /// initial send sequence number
    /// </summary>
    public UInt32 Iss { get; set; }

    /// <summary>
    /// Send properties
    /// </summary>
    public TcbSend Snd { get; set; } = new();

    /// <summary>
    /// Receive properties
    /// </summary>
    public TcbReceive Rcv { get; set; } = new();

    public class TcbSend
    {
        /// <summary>
        /// Send unacknowledged
        /// </summary>
        public UInt32 Una { get; set; }

        /// <summary>
        /// Send next
        /// </summary>
        public UInt32 Nxt { get; set; }

        /// <summary>
        /// Send window.
        /// See https://tools.ietf.org/html/rfc793#page-20
        /// </summary>
        public UInt16 Wnd { get; set; }

        /// <summary>
        /// Send urgent pointer
        /// </summary>
        public UInt16 Up { get; set; }

        /// <summary>
        /// Segment sequence number used for last window update
        /// </summary>
        public UInt32 Wl1 { get; set; }

        /// <summary>
        /// Segment acknowledgment number used for last window update
        /// </summary>
        public UInt32 Wl2 { get; set; }
    }

    public class TcbReceive
    {
        /// <summary>
        /// Receive next
        /// </summary>
        public UInt32 Nxt { get; set; }

        /// <summary>
        /// Receive window
        /// </summary>
        public UInt16 Wnd { get; set; }

        /// <summary>
        /// Receive urgent pointer
        /// </summary>
        public UInt16 Up { get; set; }
    }

    public void Reset()
    {
        Irs = 0;
        Iss = 0;
        
        Snd.Nxt=0;
        Snd.Una=0;
        Snd.Up=0;
        Snd.Wl1=0;
        Snd.Wl2=0;
        Snd.Wnd=0;
        
        Rcv.Nxt=0;
        Rcv.Wnd=0;
        Rcv.Up=0;
    }
}