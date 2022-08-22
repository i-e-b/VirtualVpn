// ReSharper disable BuiltInTypeReferenceStyle

using System.Diagnostics;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TcpProtocol;

/*
 https://blog.cloudflare.com/syn-packet-handling-in-the-wild/
 */

/// <summary>
/// Root of the custom TCP stack.
/// This tries to emulate a socket-like interface.
/// </summary><remarks>
/// Derived in part from https://github.com/frebib/netstack.git
/// </remarks>
public class TcpSocket
{
    private readonly ChildSa _tunnel;
    private static readonly Random _rnd = new();
    
    /// <summary> State of this 'socket' </summary>
    private TcpSocketState _state;
    /// <summary> State machine variables </summary>
    private TransmissionControlBlock _tcb;
    /// <summary> Maximum Segment Size </summary>
    private UInt16 _mss;
    /// <summary> Blocks of sent data, in case of retransmission </summary>
    private Dictionary<long, byte[]> _sendBuffer = new();
    /// <summary> List of incoming TCP packets </summary>
    private List<TcpSegment> _receiveQueue = new();
    /// <summary> Sequence numbers of unacknowledged segments. Sequence=>(stopwatch ticks when sent) </summary>
    private Dictionary<long, long> _unAckedSegments = new();
    /// <summary> Retransmit Time-Out (RTO) value (calculated from _rtt) </summary>
    private long _rto;
    /// <summary> Stopwatch ticks at which the last RTO was started </summary>
    private long _lastTime;
    private UInt64 _rtt,_srtt,_rttvar; // Round-trip time values
    
    /// <summary> Monotonic TCP timer </summary>
    private Stopwatch _timeWait;
    
    /// <summary> General sync lock for this socket </summary>
    /// <remarks>The locking in here is very broad, which technically could
    /// slow us down. However, we're already slow, and correct is better than fast here.</remarks>
    private readonly object _lock = new();

    public TcpSocket(ChildSa tunnel)
    {
        _tunnel = tunnel;
        _state = TcpSocketState.Closed;
        _timeWait = new Stopwatch();
        _tcb = new TransmissionControlBlock();
        _mss = TcpDefaults.DefaultMss;
    }

    /// <summary>
    /// Process an incoming tcp segment given an IPv4 wrapper
    /// </summary>
    public void ReceiveWithIpv4(TcpSegment segment, IpV4Packet wrapper) // lib/tcp/tcp.c:128
    {
        if (!segment.ValidateChecksum(wrapper))
        {
            Log.Warn($"Invalid checksum: seq={segment.SequenceNumber}");
            return; // drop the packet and await a retry.
        }

        var frame = new TcpFrame(segment, wrapper); // store this? lib/tcp/tcp.c:152
        lock (_lock)
        {
            if (_state == TcpSocketState.Closed)
            {
                ReceiveFromClosed(frame);
            }
            else if (_state == TcpSocketState.Listen)
            {
                ReceiveFromListen(frame);
            }
            else
            {
                SegmentArrives(frame);
            }

        }
    }

    private void ReceiveFromListen(TcpFrame frame)
    {
        // lib/tcp/input.c:87
        throw new NotImplementedException();
    }

    /// <summary>
    /// Handle first segment from a Closed state.
    /// Receiving from closed is a bit odd. Should normally be from Listen?
    /// </summary>
    private void ReceiveFromClosed(TcpFrame frame)
    {
        // lib/tcp/input.c:44
        Log.Debug($"Received packet. Socket state={_state.ToString()}, {frame.Ip.Source.AsString}:{frame.Tcp.SourcePort} -> {frame.Ip.Destination.AsString}:{frame.Tcp.DestinationPort}");
        
        // Filter rules:
        // - All data in the incoming segment is discarded (there should not be any)
        // - An incoming segment containing a RST is discarded
        // - An incoming segment not containing an RST causes a RST to be sent in response (this should be optional?)
        //
        // The acknowledgment and sequence field values are selected to make the
        // reset sequence acceptable to the TCP that sent the offending segment.

        if (frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Ack))
        {
            // If Ack flag is off, sequence number zero is used
            // SEQ=0; ACK=SEG.SEQ+SEG.LEN; CTL=RST,ACK.
            Log.Debug("No ACK on first message from Closed. Sending RST+ACK");
            SendRstAck(sequence: 0, ackNumber: frame.Tcp.SequenceNumber + frame.Tcp.Payload.Length);
        }
        else
        {
            // SEQ=SEG.ACK; CTL=RST
            Log.Debug("Received ACK on closed socket. Sending RST");
            SendRst(sequence: frame.Tcp.AcknowledgmentNumber);
        }

    }

    // Some helpers for 'SendEmpty' to keep the noise down
    private void SendAck() => SendEmpty(_tcb.Snd.Nxt, _tcb.Rcv.Nxt, TcpSegmentFlags.Ack);
    private void SendSynAck() => SendEmpty(_tcb.Iss, _tcb.Rcv.Nxt, TcpSegmentFlags.SynAck);
    private void SendAckFin() => SendEmpty(_tcb.Snd.Nxt++, _tcb.Rcv.Nxt, TcpSegmentFlags.Ack | TcpSegmentFlags.Fin);
    private void SendRst(long sequence) => SendEmpty(sequence, 0, TcpSegmentFlags.Rst);
    private void SendRstAck(long sequence, long ackNumber) => SendEmpty(sequence, ackNumber, TcpSegmentFlags.Rst | TcpSegmentFlags.Ack);

    private void SendEmpty(long sequence, long ackNumber, TcpSegmentFlags controlFlags)
    {
        // This should go through the tunnel?
    }
    
    /// <summary>
    /// Try to start a connection.
    /// </summary>
    private void SendSyn() // lib/tcp/output.c:47
    {
        // This should go through the tunnel.
        // Syn has a lot of rate logic
    }

    /// <summary>
    /// TCP input routine, after packet sanity checks in <see cref="ReceiveWithIpv4"/>
    /// <p></p>
    /// Follows 'SEGMENT ARRIVES':
    /// <ul>
    /// <li>https://tools.ietf.org/html/rfc793#page-65</li>
    /// <li>https://github.com/romain-jacotin/quic/blob/master/doc/TCP.md#-segment-arrives</li>
    /// <li>See RFC793, bottom of page 52: https://tools.ietf.org/html/rfc793#page-52</li>
    /// </ul>
    /// </summary>
    private void SegmentArrives(TcpFrame frame)
    {
        // lib/tcp/input.c:228
    }

    private void UpdateWindow(TcpSegment segment) // tcp_update_wnd -> lib/tcp/input.c:1062
    {
        _tcb.Snd.Wnd = (ushort)segment.WindowSize;
        _tcb.Snd.Wl1 = (uint)segment.SequenceNumber;
        _tcb.Snd.Wl2 = (uint)segment.AcknowledgmentNumber;
    }

    /// <summary>
    /// Sequence validation
    /// </summary>
    private bool AckAcceptable(TransmissionControlBlock tcb, int ackNumber)
    {
        return SeqLeq(tcb.Snd.Una, ackNumber) && SeqLeq(ackNumber, tcb.Snd.Nxt);
    }
    
    // using long to save casting syntax around signed/unsigned 16&32 values
    
    private static bool SeqLt(long a, long b) => (a-b) < 0;
    private static bool SeqGt(long a, long b) => (a-b) > 0;
    private static bool SeqLeq(long a, long b) => (a-b) <= 0;
    private static bool SeqGeq(long a, long  b) => (a-b) >= 0;
    private static bool SeqInRange(long seq, long start, long end) => (seq - start) < (end - start);
    private static bool SeqInWindow(long seq, long start, long size) => SeqInRange(seq, start, start + size);
}