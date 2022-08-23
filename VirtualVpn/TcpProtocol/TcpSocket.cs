// ReSharper disable BuiltInTypeReferenceStyle

using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
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
    /// <summary>
    /// .Net standard codes for socket errors
    /// </summary>
    public SocketError ErrorCode { get; set; }
    
    #region Private state
    /// <summary> Tunnel interface (used instead of sockets) </summary>
    private readonly ITransportTunnel _tunnel;
    private readonly ITcpAdaptor _adaptor;
    private volatile bool _running;

    /// <summary> State of this 'socket' </summary>
    private TcpSocketState _state;
    /// <summary> State machine variables </summary>
    private TransmissionControlBlock _tcb;
    /// <summary> Maximum Segment Size </summary>
    private UInt16 _mss;
    /// <summary> Blocks of sent data, in case of retransmission </summary>
    private SendBuffer _sendBuffer = new();
    /// <summary> Sorted list of incoming TCP packets </summary>
    private ReceiveBuffer _receiveQueue = new();
    /// <summary> Sequence numbers of unacknowledged segments.</summary>
    private Queue<TcpTimedSequentialData> _unAckedSegments = new();
    
    /// <summary> Retransmit Time-Out (RTO) value (calculated from _rtt) </summary>
    private TimeSpan _rto;
    private UInt64 _rtt,_srtt,_rttvar; // Round-trip time values
    
    /// <summary> Monotonic TCP timer </summary>
    private Stopwatch _timeWait;
    
    /// <summary> General sync lock for this socket </summary>
    /// <remarks>The locking in here is very broad, which technically could
    /// slow us down. However, we're already slow, and correct is better than fast here.</remarks>
    private readonly object _lock = new();

    /// <summary>
    /// Captured routing information from start of connection
    /// </summary>
    private readonly TcpRoute _route;

    /// <summary>
    /// Possible 'early' data from handshake
    /// </summary>
    private byte[] _earlyPayload;

    private int _backoff;

    private readonly AutoResetEvent _sendWait;
    private readonly AutoResetEvent _readWait;
    private TcpTimedRtoEvent? _rtoEvent; // most recent retransmit timeout, if any

    #endregion

    /// <summary>
    /// Create a new virtual TCP socket interface for the VPN tunnel
    /// </summary>
    public TcpSocket(ITransportTunnel tunnel, ITcpAdaptor adaptor)
    {
        ErrorCode = SocketError.Success;
        
        _tunnel = tunnel;
        _adaptor = adaptor;
        
        _state = TcpSocketState.Closed;
        _mss = TcpDefaults.DefaultMss;
        
        _timeWait = new Stopwatch();
        _tcb = new TransmissionControlBlock();
        _route = new TcpRoute();
        _sendWait = new AutoResetEvent(true);
        _readWait = new AutoResetEvent(true);
    }

    /// <summary>
    /// Drive any time-based functions.
    /// This needs to be called periodically.
    /// </summary>
    public void EventPump()
    {
        _rtoEvent?.TriggerIfExpired();
        // TODO: check for any other timers that need driving through this
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
                SegmentArrived(frame);
            }
        }
    }

    /// <summary>
    /// Socket is idle and waiting for a connection.
    /// We SHOULD get a SYN as the start of the handshake.
    /// </summary>
    private void ReceiveFromListen(TcpFrame frame)
    {
        // lib/tcp/input.c:87
        Log.Info($"Received packet. Socket state={_state.ToString()}, {frame.Ip.Source}:{frame.Tcp.SourcePort} -> {frame.Ip.Destination}:{frame.Tcp.DestinationPort}");
        
        // Ignore any reset packets
        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Rst))
        {
            Log.Debug("Reset flag set. Ignoring packet.");
            return;
        }
        
        // Check for ACK
        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Ack))
        {
            // Any acknowledgment is bad if it arrives on a connection still in
            // the LISTEN state.  An acceptable reset segment should be formed
            // for any arriving ACK-bearing segment
            Log.Warn("Invalid message: ACK send to listening socket. Will send RST.");
            SendRst(frame.Tcp.AcknowledgmentNumber);
            return;
        }
        
        // Make sure SYN is present
        if (frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Syn))
        {
            // lib/tcp/input.c:138
            return;
        }
        
        /*
        If the SYN bit is set, check the security.  If the
        security/compartment on the incoming segment does not exactly
        match the security/compartment in the TCB then send a reset and
        return.

          <SEQ=SEG.ACK><CTL=RST>
          
        If the SEG.PRC is greater than the TCB.PRC then if allowed by
        the user and the system set TCB.PRC<-SEG.PRC, if not allowed
        send a reset and return.

          <SEQ=SEG.ACK><CTL=RST>

        If the SEG.PRC is less than the TCB.PRC then continue.

        Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other
        control or text should be queued for processing later.  ISS
        should be selected and a SYN segment sent of the form:

          <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

        SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
        state should be changed to SYN-RECEIVED.  Note that any other
        incoming control or data (combined with SYN) will be processed
        in the SYN-RECEIVED state, but processing of SYN and ACK should
        not be repeated.  If the listen was not fully specified (i.e.,
        the foreign socket was not fully specified), then the
        unspecified fields should be filled in now.
         */
        
        // lib/tcp/input.c:173
        var iss = NewTcpSequence();   // initial sequence on our side
        var segSeq = frame.Tcp.SequenceNumber;
        
        _route.LocalPort = frame.Tcp.DestinationPort; // as we are the listener
        _route.LocalAddress = frame.Ip.Destination;
        _route.RemotePort = frame.Tcp.SourcePort;
        _route.RemoteAddress = frame.Ip.Source;
        
        _mss = 1460;
        
        _tcb.Irs = (uint)segSeq;
        _tcb.Iss = iss;
        
        _tcb.Snd.Una = iss;
        _tcb.Snd.Nxt = iss + 1;
        _tcb.Snd.Wnd = (ushort)frame.Tcp.WindowSize;
        
        _tcb.Rcv.Nxt = (uint)(segSeq + 1);
        _tcb.Rcv.Wnd = UInt16.MaxValue;
        
        SetState(TcpSocketState.SynReceived);
        
        Log.Info("Ready for connection. Sending SYN+ACK");
        SendSynAck();
    }

    private void SetState(TcpSocketState newState) // lib/tcp/tcp.c:178
    {
        Log.Debug($"Transition from state {_state.ToString()} to {newState.ToString()}");
        
        lock (_lock)
        {
            _state = newState;

            switch (newState)
            {
                case TcpSocketState.Closing:
                case TcpSocketState.CloseWait:
                    // Should and any blocking calls to Receive
                    EndAllReceive();
                    break;
                
                case TcpSocketState.Closed:
                    // Should signal to the adaptor that we are gone
                    KillSession();
                    break;
            }
        }
    }

    /// <summary>
    /// Signal to adaptor that we are no longer a valid socket.
    /// That should remove any resources and close down timers.
    /// </summary>
    private void KillSession()
    {
        _timeWait.Stop();
        _adaptor.Close();
    }

    /// <summary>
    /// cancel any blocking receive calls
    /// </summary>
    private void EndAllReceive()
    {
        _running = false; // TODO any receive waits should be checking this
        _readWait.Set();
    }

    /// <summary>
    /// Generate a new random sequence
    /// </summary>
    private static UInt32 NewTcpSequence() // lib/tcp/tcp.c:352
    {
        var bytes = new byte[4];
        RandomNumberGenerator.Fill(bytes);
        bytes[0] &= 0x3F; // give ourself over half the space free to make debugging easier. Remove this if you're confident!
        return Bit.BytesToUInt32(bytes);
    }

    /// <summary>
    /// Handle first segment from a Closed state.
    /// Receiving from closed is a bit odd. Should normally be from Listen?
    /// </summary>
    private void ReceiveFromClosed(TcpFrame frame)
    {
        // lib/tcp/input.c:44
        Log.Info($"Received packet. Socket state={_state.ToString()}, {frame.Ip.Source}:{frame.Tcp.SourcePort} -> {frame.Ip.Destination}:{frame.Tcp.DestinationPort}");
        
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

    private void SendEmpty(long sequence, long ackNumber, TcpSegmentFlags controlFlags) // include/netstack/tcp/tcp.h:473, lib/tcp/output.c:100
    {
        // This should go through the tunnel. We don't need to do any routing ourselves.
        
        // lib/tcp/output.c:117
        var seg = new TcpSegment
        { // lib/tcp/output.c:256
            SourcePort = _route.LocalPort,
            DestinationPort = _route.RemotePort,
            SequenceNumber = sequence,
            AcknowledgmentNumber = ackNumber,
            DataOffset = 5,
            Reserved = 0,
            Flags = controlFlags,
            WindowSize = _tcb.Rcv.Wnd,
            Checksum = 0,
            UrgentPointer = 0,
            Options = Array.Empty<byte>(),
            Payload = Array.Empty<byte>()
        };
        
        QueueUnacknowledged(sequence, 0, controlFlags);
        
        Send(seg, _route);
    }

    private void Send(TcpSegment seg, TcpRoute route) // lib/tcp/output.c:16
    {
        // Normally, we would construct some data and send it on a
        // physical device.
        // Here, we pass to a tunnel
        
        _adaptor.Reply(seg, route);
    }

    /// <summary>
    /// Adds an outgoing segment to the unacknowledged queue in case it is required for
    /// later retransmission. This can be used for both data and control packets
    /// </summary>
    private void QueueUnacknowledged(long sequence, int dataLength, TcpSegmentFlags flags) // lib/tcp/output.c:219
    {
        // Start re-transmission timeout if needed
        if (_unAckedSegments.Count < 1) StartRto(dataLength, flags);
        
        // Don't queue segment if it is a retransmission
        if (sequence != _tcb.Snd.Nxt)
        {
            Log.Debug($"Not queueing segment for sequence {sequence} (SND.NXT={_tcb.Snd.Nxt})");
            return;
        }
        
        // Don't queue empty ACK packets
        if (dataLength < 1 && flags == TcpSegmentFlags.Ack)
        {
            Log.Debug($"Not queueing ACK at sequence {sequence} -- it is empty");
            return;
        }

        // Don't duplicate
        if (_unAckedSegments.Any(item => item.Sequence == sequence))
        {
            Log.Debug($"Not queueing ACK at sequence {sequence} -- already in list");
            return;
        }

        Log.Debug($"Adding segment to un-ack queue. Seq={sequence}, flags={flags.ToString()}"); // lib/tcp/output.c:238
        
        // Store sequence information for the RTO
        _unAckedSegments.Enqueue(new TcpTimedSequentialData{
            Sequence = sequence,
            Flags = flags,
        });
        
        // Advance SND.NXT past this segment
        _tcb.Snd.Nxt += (uint)dataLength;
    }

    private void StartRto(int dataLength, TcpSegmentFlags flags) // lib/tcp/retransmission.c:46
    {
        // This is a highly simplified retry clock.
        _rtoEvent = new TcpTimedRtoEvent{
            Sequence = _tcb.Snd.Nxt,
            Length = dataLength,
            Flags = flags,
            Action = RetransmissionTimeout, // Source had this as null. I think it should be 'tcp_retransmission_timeout' ( lib/tcp/retransmission.c:68 )
            Timeout = TcpDefaults.InitialRto
        };
    }

    private void RetransmissionTimeout(TcpTimedRtoEvent evt) // lib/tcp/retransmission.c:68
    {
        lock (_lock)
        {
            // Attempt to re-send un-acknowledged data
            // There should only be one at a time?

            // Maximum value MAY be placed on RTO, provided it is at least 60 seconds ( https://tools.ietf.org/html/rfc6298 )
            if (_rto.TotalSeconds < 60) _backoff++;
            
            var seq = evt.Sequence;
            var una = _tcb.Snd.Una;
            var end = seq + evt.Length - 1;
            
            Log.Debug($"Retransmission timeout. Seq={seq}, Iss={_tcb.Iss}, data len={evt.Length}.");
            
            // Retransmit a new segment starting from the latest un-acked data
            if (SeqLtEq(una, end)) // lib/tcp/retransmission.c:88
            {
                var bot = seq - _tcb.Iss;
                var top = end - _tcb.Iss;
                Log.Warn($"Retransmit sequence range {bot} -> {top}");
                
                // Always exponentially backoff every time a segment has to be
                // retransmitted. This is reset to 0 every time a valid ACK arrives (see ResetBackoff() )
                _backoff++;
                
                // Retransmit waiting data.
                if (evt.Length > 0)
                {
                    Log.Info($"Retransmit data. Seq={una}, Byte count={evt.Length} Flags={evt.Flags.ToString()}");
                    SendData(sequence: una, size: evt.Length, flags: evt.Flags);
                }
                else
                {
                    Log.Info($"Retransmit empty. Seq={una}, Flags={evt.Flags.ToString()}");
                    SendEmpty(una, 0, evt.Flags);
                }
            }

            // If there are no more segments waiting to be acknowledged, don't schedule another check
            if (_unAckedSegments.Count <= 0)
            {
                _rtoEvent = null;
                return; // lib/tcp/retransmission.c:114
            }

            // Update the next unacknowledged segment for retransmit timeout
            var waiting = _unAckedSegments.Peek();

            var data = _sendBuffer[waiting.Sequence];
            var next = new TcpTimedRtoEvent
            {
                Sequence = (uint)waiting.Sequence,
                Length = data.Length,
                Flags = TcpSegmentFlags.None,
                Action = RetransmissionTimeout,
                Timeout = TcpDefaults.InitialRto.Multiply(_backoff)
            };
                
            Log.Debug($"Backoff for next retransmit: {next.Timeout}");
                
            _rtoEvent = next;
        }
    }

    /// <summary>
    /// Constructs and sends a TCP packet with the largest payload available to send,
    /// or as much as can fit in a single packet, from the socket data send queue.
    /// </summary>
    private void SendData(uint sequence, int size, TcpSegmentFlags flags) // lib/tcp/output.c:135
    {
        // lib/tcp/output.c:153
        var ackN = _tcb.Rcv.Nxt;
        flags |= TcpSegmentFlags.Ack;
        
        var bytesAvailable = _sendBuffer.Count();
        if (bytesAvailable < 1)
        {
            ErrorCode = SocketError.NoData;
            Log.Error("Call to SendData, with no data in outgoing buffer");
            return;
        }
        
        var seg = new TcpSegment
        { // lib/tcp/output.c:161
            SourcePort = _route.LocalPort,
            DestinationPort = _route.RemotePort,
            SequenceNumber = sequence,
            AcknowledgmentNumber = ackN,
            DataOffset = 5,
            Reserved = 0,
            Flags = flags,
            WindowSize = _tcb.Rcv.Wnd,
            Checksum = 0,
            UrgentPointer = 0,
            Options = Array.Empty<byte>(),
            Payload = Array.Empty<byte>()
        };
        
        // NOTE: logic here was changed from source...
        
        // Find the largest possible segment payload with headers taken into account
        // then clamp the value to at most the requested payload size
        // https://tools.ietf.org/html/rfc793#section-3.7
        // (see https://tools.ietf.org/html/rfc879 for details)
        var willFitInPacket = Min(_mss, (int)bytesAvailable);
        
        // Make sure we don't send more than requested
        var toSend = (size > 0) ? Min(size, willFitInPacket) : willFitInPacket;
        
        // Set 'push' flag if the buffer is going to be empty
        if (toSend >= bytesAvailable) seg.Flags |= TcpSegmentFlags.Psh;
        
        // Add to queue waiting for ACK
        QueueUnacknowledged(sequence, toSend, seg.Flags);
        
        seg.Payload = _sendBuffer.Pull(sequence, toSend); // lib/tcp/output.c:194

        if (seg.Payload.Length <= 0)
        {
            Log.Warn("No data to read");
            ErrorCode = SocketError.NoData;
            return;
        }
        
        Send(seg, _route); // lib/tcp/output.c:212
    }

    /// <summary>
    /// Try to start a connection.
    /// </summary>
    private void SendSyn() // lib/tcp/output.c:47
    {
        // This should go through the tunnel.
        // Syn has a lot of rate logic
        
        var seg = new TcpSegment
        { // lib/tcp/output.c:256
            SourcePort = _route.LocalPort,
            DestinationPort = _route.RemotePort,
            SequenceNumber = _tcb.Iss,
            AcknowledgmentNumber = 0,
            DataOffset = 5,
            Reserved = 0,
            Flags = TcpSegmentFlags.Syn,
            WindowSize = _tcb.Rcv.Wnd,
            Checksum = 0,
            UrgentPointer = 0,
            Options = Array.Empty<byte>(),
            Payload = Array.Empty<byte>()
        };

        // Start the SYN connect timeout if this is the first SendSyn() call
        // The timer will be rescheduled each time on expiry
        if (_backoff < 1)
        {
            Log.Debug("Starting SYN RTO");
            
            _rtoEvent = new TcpTimedRtoEvent{ // lib/tcp/output.c:79
                Sequence = _tcb.Iss,
                Length = 0,
                Flags = TcpSegmentFlags.Syn,
                Action = SynRetransmissionTimeout,
                Timeout = TcpDefaults.InitialRto
            };
        }
        
        Send(seg, _route);
    }

    private void SynRetransmissionTimeout(TcpTimedRtoEvent eventData) // lib/tcp/retransmission.c:10
    {
        lock (_lock)
        {
            if (_state != TcpSocketState.SynSent) // no longer in a valid state (might have connected?)
            {
                _backoff = 0;
                _rtoEvent = null;
                return;
            }

            if (_backoff >= TcpDefaults.BackoffLimit) // timed out waiting for a response
            {
                SetState(TcpSocketState.Closed);
                ErrorCode = SocketError.TimedOut;
                _sendWait.Set();
                _readWait.Set();
                return;
            }
            
            // Send the next SYN attempt
            _backoff++;
            SendSyn();
            
            // Reset the RTO event to try again (double the previous timeout)
            eventData.Timeout = eventData.Timeout.Multiply(2);
            eventData.Timer.Restart();
            _rtoEvent = eventData;
        }
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
    private void SegmentArrived(TcpFrame frame)
    {
        // lib/tcp/input.c:228
        var segSeq = (uint)frame.Tcp.SequenceNumber;
        var segAck = (uint)frame.Tcp.AcknowledgmentNumber;
        var segLen = frame.Tcp.Payload.Length;
        var segEnd = segSeq + Max(segLen - 1, 0);
        
        // A segment is in-order if the sequence number is what we expect.
        // This should be the case in our VPN scenario, but not guaranteed.
        var inOrder = segSeq == _tcb.Rcv.Nxt;
        var ackOk = AckAcceptable(segAck);

        if (_state == TcpSocketState.SynSent) // lib/tcp/input.c:257
        {
            HandleSynSent(frame, segAck, ackOk, segSeq);
            return;
        }

        if (!ValidateReceptionWindow(segLen, segSeq, segEnd))
        {
            if (!frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Rst) || _state == TcpSocketState.TimeWait) return;
            Log.Debug("Invalid sequence, but not in time-wait. Sending ACK");
            SendAck();
            return;
        }
        
        if (CheckResetBit(frame)) return;

        // Ignoring precedence checks
        
        CheckForSynInReceptionWindow(frame, segSeq, segAck);

        // lib/tcp/input.c:662
        // "if the ACK bit is off drop the segment and return"
        if (frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Ack)) return;

        if (HandleIncomingAckFlag(frame, ackOk, segSeq, segAck)) return;

        if (HandleShutdownAcks(inOrder)) return;

        // Ignoring urgent flag

        // Handle actual input data
        ProcessSegmentData(frame, segLen, inOrder);
        
        // Filter FIN flag
        if (DropIfFinFlagsInvalid(frame, segSeq)) return;

        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Fin))
        {
            /*
              If the FIN bit is set, signal the user "connection closing" and
              return any pending RECEIVE packets with same message, advance RCV.NXT
              over the FIN, and send an acknowledgment for the FIN.  Note that
              FIN implies PUSH for any segment text not yet delivered to the
              user.
            */
            switch (_state) // lib/tcp/input.c:978
            {
                case TcpSocketState.SynReceived: // lib/tcp/input.c:985
                case TcpSocketState.Established:
                    SetState(TcpSocketState.CloseWait);
                    break;
                case TcpSocketState.FinWait1: // lib/tcp/input.c:997
                {
                    /*
                    FIN-WAIT-1 STATE
            
                      If our FIN has been ACKed (perhaps in this segment), then
                      enter TIME-WAIT, start the time-wait timer, turn off the other
                      timers; otherwise enter the CLOSING state.
                    */
                    if (FinWasAcked())
                    {
                        SetState(TcpSocketState.TimeWait);
                        _timeWait.Restart();
                    }
                    else
                    {
                        SetState(TcpSocketState.Closing);
                    }

                    break;
                }
                case TcpSocketState.FinWait2: // lib/tcp/input.c:1016
                    SetState(TcpSocketState.TimeWait);
                    _timeWait.Restart();
                    break;
                case TcpSocketState.TimeWait: // lib/tcp/input.c:1030
                    _timeWait.Restart();
                    break;
                // Other states stay as-is
            }
            
            // We are now "EOF"
            _readWait.Set();
            
            Log.Debug("End of stream. Sending ACK");
            _tcb.Rcv.Nxt = segSeq + 1;
            SendAck();
        }

        Log.Debug("End of receive");
    }

    private bool DropIfFinFlagsInvalid(TcpFrame frame, uint segSeq)
    {
        /*
          check the FIN bit,

          Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
          since the SEG.SEQ cannot be validated; drop the segment and
          return.
        */
        if (frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Fin))
        {
            switch (_state) // lib/tcp/input.c:957
            {
                case TcpSocketState.Closed:
                case TcpSocketState.Listen:
                case TcpSocketState.SynSent:
                    Log.Warn($"State {_state.ToString()} is invalid for a non-FIN packet. Dropping.");
                    return true;
                // other states continue
            }
        }
        else // there is a FIN flag
        {
            if (segSeq != _tcb.Rcv.Nxt)
            {
                Log.Warn($"Received out of order FIN packet. Ignoring. SEQ={segSeq}, RCV.NXT={_tcb.Rcv.Nxt}");
                return true;
            }
        }

        return false;
    }

    private void ProcessSegmentData(TcpFrame frame, int segLen, bool inOrder)
    {
        switch (_state) // lib/tcp/input.c:859
        {
            case TcpSocketState.Established: // lib/tcp/input.c:889
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            {
                /*
                  States: ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2.
            
                    Once in the ESTABLISHED state, it is possible to deliver segment
                    text to user RECEIVE buffers.  Text from segments can be moved
                    into buffers until either the buffer is full or the segment is
                    empty.  If the segment empties and carries an PUSH flag, then
                    the user is informed, when the buffer is returned, that a PUSH
                    has been received.
            
                    When the TCP takes responsibility for delivering the data to the
                    user it must also acknowledge the receipt of the data.
            
                    Once the TCP takes responsibility for the data it advances
                    RCV.NXT over the data accepted, and adjusts RCV.WND as
                    appropriate to the current buffer availability.  The total of
                    RCV.NXT and RCV.WND should not be reduced.
            
                    Please note the window management suggestions in section 3.7.
            
                    Send an acknowledgment of the form:
            
                      <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            
                    This acknowledgment should be piggybacked on a segment being
                    transmitted if possible without incurring undue delay.
                */
                if (segLen < 1) break; // no data

                _receiveQueue.Insert(frame.Tcp);

                // Segments take up space in the receive window regardless
                // of being in-order. Adjust the window:
                _tcb.Rcv.Wnd -= (ushort)segLen;

                Log.Debug($"Segment queued. {segLen} bytes");

                // Calculate and Acknowledge the largest contiguous segment we have
                _tcb.Rcv.Nxt = _receiveQueue.ContiguousSequence();
                SendAck();

                if (inOrder)
                {
                    _readWait.Set(); // unlock readers
                }

                break;
            }

            case TcpSocketState.Closed: // lib/tcp/input.c:945
            case TcpSocketState.CloseWait:
            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            case TcpSocketState.TimeWait:
                Log.Warn($"Received a data segment in {_state.ToString()} state. Ignoring.");
                break;


            case TcpSocketState.Listen:
            case TcpSocketState.SynSent:
            case TcpSocketState.SynReceived:
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private bool HandleShutdownAcks(bool inOrder)
    {
        if (!inOrder || !FinWasAcked()) return false; // lib/tcp/input.c:768
        
        switch (_state)
        {
            case TcpSocketState.FinWait1: // lib/tcp/input.c:777
                /*
                        FIN-WAIT-1 STATE

                          In addition to the processing for the ESTABLISHED state, if
                          our FIN is now acknowledged then enter FIN-WAIT-2 and continue
                          processing in that state.
                    */
                SetState(TcpSocketState.FinWait2);
                break;
            case TcpSocketState.FinWait2: // lib/tcp/input.c:787
                /*
                        FIN-WAIT-2 STATE
                
                          In addition to the processing for the ESTABLISHED state, if
                          the retransmission queue is empty, the user's CLOSE can be
                          acknowledged ("ok") but do not delete the TCB.
                    */
                // TODO: trigger anything that need to happen when close is acknowledged.
                break;
            case TcpSocketState.Closing: // lib/tcp/input.c:798
                /*
                        CLOSING STATE
                
                          In addition to the processing for the ESTABLISHED state, if
                          the ACK acknowledges our FIN then enter the TIME-WAIT state,
                          otherwise ignore the segment.
                    */
                SetState(TcpSocketState.TimeWait);
                _timeWait.Restart();
                // TODO: anything waiting on close can continue now
                break;
            case TcpSocketState.LastAck: // lib/tcp/input.c:813
                /*
                        LAST-ACK STATE
                
                          The only thing that can arrive in this state is an
                          acknowledgment of our FIN.  If our FIN is now acknowledged,
                          delete the TCB, enter the CLOSED state, and return.
                    */
                SetState(TcpSocketState.Closed);
                _tcb.Reset();
                return true;
            case TcpSocketState.TimeWait: // lib/tcp/input.c:825
                /*
                        TIME-WAIT STATE
                
                          The only thing that can arrive in this state is a
                          retransmission of the remote FIN.  Acknowledge it, and restart
                          the 2 MSL timeout.
                    */
                SendAck();
                _timeWait.Restart();
                break;

            case TcpSocketState.Closed:
            case TcpSocketState.Listen:
            case TcpSocketState.SynSent:
            case TcpSocketState.SynReceived:
            case TcpSocketState.Established:
            case TcpSocketState.CloseWait:
                break;

            default:
                throw new ArgumentOutOfRangeException();
        }

        return false;
    }

    /// <summary>
    /// The ACK for the FIN is the sequence number _after_ the last byte sent.
    /// This can only be reached when SND.NXT is incremented when the FIN is sent
    /// </summary>
    private bool FinWasAcked() // include/netstack/tcp/tcp.h:418
    {
        return _tcb.Snd.Una == (_sendBuffer.Start + _sendBuffer.Count() + 1);
    }

    private bool HandleIncomingAckFlag(TcpFrame frame, bool ackOk, uint segSeq, uint segAck) // lib/tcp/input.c:682
    {
        switch (_state)
        {
            case TcpSocketState.SynReceived:
                if (ackOk)
                {
                    // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state and continue processing.
                    ConnectionEstablished(segSeq);
                }
                else
                {
                    // If the segment acknowledgment is not acceptable, form a reset segment, and send it.
                    Log.Warn("Would have established connection, but ACK was not acceptable. Sending RST and returning to Listen");
                    SendRst(segAck);
                    RestoreListenState();
                }

                break;

            case TcpSocketState.Established: // lib/tcp/input.c:719
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            case TcpSocketState.CloseWait:
            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            {
                /* ESTABLISHED STATE

                      If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
                      Any segments on the retransmission queue which are thereby
                      entirely acknowledged are removed.  Users should receive
                      positive acknowledgments for buffers which have been SENT and
                      fully acknowledged (i.e., SEND buffer should be returned with
                      "ok" response).  If the ACK is a duplicate
                      (SEG.ACK < SND.UNA), it can be ignored.  If the ACK acks
                      something not yet sent (SEG.ACK > SND.NXT) then send an ACK,
                      drop the segment, and return.

                      If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be
                      updated.  If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
                      SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
                      SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK.

                      Note that SND.WND is an offset from SND.UNA, that SND.WL1
                      records the sequence number of the last segment used to update
                      SND.WND, and that SND.WL2 records the acknowledgment number of
                      the last segment used to update SND.WND.  The check here
                      prevents using old segments to update the window.
                */

                if (ackOk)
                {
                    // RFC 1122: Section 4.2.2.20 (g)
                    // TCP event processing corrections
                    // https://tools.ietf.org/html/rfc1122#page-94

                    _tcb.Snd.Una = segAck; // update send buffer
                    UpdateRtq(); // Remove any segments from the rtq that are ACKd

                    ResetBackoff();
                    _sendWait.Set(); // there might be newly available space in the send window

                    if (SeqGt(segAck, _tcb.Snd.Nxt) && !SeqLt(segAck, _tcb.Snd.Una))
                    {
                        Log.Warn("Received an ACK for something we didn't send");
                        return true;
                    }
                }

                // If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK))
                if (SeqLt(_tcb.Snd.Wl1, segSeq) || (_tcb.Snd.Wl1 == segSeq && SeqLtEq(_tcb.Snd.Wl2, segAck)))
                {
                    UpdateWindow(frame.Tcp);
                }
                else
                {
                    _tcb.Snd.Wnd = (ushort)frame.Tcp.WindowSize;
                }

                break;
            }
        }

        return false;
    }

    private void ResetBackoff()
    {
        // Exponential backoff should be reset upon receiving a valid ACK
        // It should happen AFTER updating the rtt/rtq so that segments
        // acknowledged by this ACK segment aren't used to calculate the
        // updated RTO. See: https://tools.ietf.org/html/rfc6298#page-4
        _backoff = 0;
    }

    private void RestoreListenState()
    {
        SetState(TcpSocketState.Listen);
        _tcb.Reset();
    }

    private void ConnectionEstablished(uint segSeq) // lib/tcp/tcp.c:198
    {
        SetState(TcpSocketState.Established);
        
        _rtoEvent = null; // cancel syn-sent timer
        
        Log.Debug($"Tcp session: first byte={segSeq}, SND.WND={_tcb.Snd.Wnd}, RCV.WND={_tcb.Rcv.Wnd}");
        
        // The source does set-up of the send buffer here, but we handle it dynamically
    }

    private bool CheckResetBit(TcpFrame frame) // lib/tcp/input.c:509
    {
        /*
        In the following it is assumed that the segment is the idealized
        segment that begins at RCV.NXT and does not exceed the window.
        One could tailor actual segments to fit this assumption by
        trimming off any portions that lie outside the window (including
        SYN and FIN), and only processing further if the segment then
        begins at RCV.NXT.  Segments with higher beginning sequence
        numbers may be held for later processing.

        TODO: Store out-of-order segments that are >RCV.NXT for later processing
        Not required, as the packet should get re-sent, but would reduce network use.

        second check the RST bit,
        */
        switch (_state)
        {
            case TcpSocketState.SynReceived:
                if (IsSynReceivedWithReset(frame)) return true;
                break;

            case TcpSocketState.Established:
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            case TcpSocketState.CloseWait:
                if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Rst))
                {
                    /*
                      ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT

                        If the RST bit is set then, any outstanding RECEIVEs and SEND
                        should receive "reset" responses.  All segment queues should be
                        flushed.  Users should also receive an unsolicited general
                        "connection reset" signal.  Enter the CLOSED state, delete the
                        TCB, and return.

                    */
                    SetState(TcpSocketState.Closed);
                    Log.Warn("Received RST flagged message during handshake");
                    ErrorCode = SocketError.ConnectionReset;
                    throw new SocketException((int)ErrorCode);
                }

                break;

            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            case TcpSocketState.TimeWait:
                if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Rst))
                {
                    /*
                      CLOSING STATE, LAST-ACK STATE, TIME-WAIT,
                      
                        If the RST bit is set then, enter the CLOSED state, delete the
                        TCB, and return.
                    */
                    SetState(TcpSocketState.Closed);
                    Log.Warn("Received RST flagged message during handshake");
                    ErrorCode = SocketError.ConnectionReset;
                    throw new SocketException((int)ErrorCode);
                }

                break;
        }

        return false;
    }

    private void CheckForSynInReceptionWindow(TcpFrame frame, uint segSeq, uint segAck) // lib/tcp/input.c:628
    {
        /*
         Check the SYN bit:

          SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT,

        If the SYN is in the window it is an error, send a reset, any
        outstanding RECEIVEs and SEND should receive "reset" responses,
        all segment queues should be flushed, the user should also
        receive an unsolicited general "connection reset" signal, enter
        the CLOSED state, delete the TCB, and return.

        If the SYN is not in the window this step would not be reached
        and an ack would have been sent in the first step (sequence
        number check).
         */

        switch (_state)
        {
            case TcpSocketState.SynReceived:
            case TcpSocketState.Established:
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            case TcpSocketState.CloseWait:
            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            case TcpSocketState.TimeWait:
                // if SYN set, and sequence is outside the window
                if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Syn)
                    && (segSeq < _tcb.Rcv.Nxt || segSeq > (_tcb.Rcv.Nxt + _tcb.Rcv.Wnd)))
                {
                    Log.Warn("SYN set and sequence out of reception window");
                    SendRst(segAck);
                    ErrorCode = SocketError.ConnectionReset;
                    throw new SocketException((int)ErrorCode);

                    // Note: there is an RFC that should be followed here
                    // to prevent reset attacks. Not critical in tunnel scenario.
                    //RFC 5961 Section 4: Blind Reset Attack on SYN -- https://tools.ietf.org/html/rfc5961#page-9
                }

                break;

            case TcpSocketState.Closed:
            case TcpSocketState.Listen:
            case TcpSocketState.SynSent:
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    private bool IsSynReceivedWithReset(TcpFrame frame) // lib/tcp/input.c:509
    {
        /*
          SYN-RECEIVED STATE

            If the RST bit is set

              If this connection was initiated with a passive OPEN (i.e.,
              came from the LISTEN state), then return this connection to
              LISTEN state and return.  The user need not be informed.  If
              this connection was initiated with an active OPEN (i.e., came
              from SYN-SENT state) then the connection was refused, signal
              the user "connection refused".  In either case, all segments
              on the retransmission queue should be removed.  And in the
              active OPEN case, enter the CLOSED state and delete the TCB,
              and return.
        */
        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Rst))
        {
            Log.Warn("Received RST flagged message during handshake");
            ErrorCode = SocketError.ConnectionRefused;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Check that sequence and data range are valid
    /// </summary>
    private bool ValidateReceptionWindow(int segLen, uint segSeq, long segEnd)
    {
        /* For states: SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT.

            Segments are processed in sequence.  Initial tests on arrival
            are used to discard old duplicates, but further processing is
            done in SEG.SEQ order.  If a segment's contents straddle the
            boundary between old and new, only the new parts should be
            processed.

            There are four cases for the acceptability test for an incoming
            segment:

            Segment Receive  Test
            Length  Window
            ------- -------  -------------------------------------------

               0       0     SEG.SEQ = RCV.NXT

               0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND

              >0       0     not acceptable

              >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
                          or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

            If the RCV.WND is zero, no segments will be acceptable, but
            special allowance should be made to accept valid ACKs, URGs and
            RSTs.
        */
        var valid = true;
        if (segLen > 0 && _tcb.Rcv.Wnd == 0)
        {
            valid = false;
            Log.Warn("Received data, but RCV.WND = 0");
        }

        if (!SeqInWindow(segSeq, _tcb.Rcv.Nxt, _tcb.Rcv.Wnd)
            || !SeqInWindow(segEnd, _tcb.Rcv.Nxt, _tcb.Rcv.Wnd))
        {
            valid = false;
            Log.Warn($"Received out of sequence segment. SEQ {segSeq} < RCV.NXT {_tcb.Rcv.Nxt}");
        }

        if (!SeqInWindow(segEnd, _tcb.Rcv.Nxt, _tcb.Rcv.Wnd))
        {
            valid = false;
            Log.Warn($"More data sent that fits in negotiated window. SEQ={segSeq}, End={segEnd}, Length={segLen}, RCV.NXT={_tcb.Rcv.Nxt}, RCV.WND={_tcb.Rcv.Wnd}");
        }

        return valid;
    }


    private static int Min(int a, int b) => a < b ? a : b;
    private static int Max(int a, int b) => a > b ? a : b;

    private void HandleSynSent(TcpFrame frame, uint segAck, bool ackOk, uint segSeq) // lib/tcp/input.c:257
    {
        Log.Debug($"Packet arrived after SYN sent (remote {_route.RemoteAddress}:{_route.RemotePort})");
        /*If the ACK bit is set

              If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset (unless
              the RST bit is set, if so drop the segment and return)

                <SEQ=SEG.ACK><CTL=RST>

              and discard the segment.  Return.

              If SND.UNA =< SEG.ACK =< SND.NXT then the ACK is acceptable.*/
        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Ack))
        {
            if (SeqLt(segAck, _tcb.Iss)
                || SeqGt(segAck, _tcb.Snd.Nxt))
            {
                if (frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Rst))
                {
                    SendRst(segAck);
                }

                return;
            }
        }

        /*If the RST bit is set

              If the ACK was acceptable then signal the user "error:
              connection reset", drop the segment, enter CLOSED state,
              delete TCB, and return.  Otherwise (no ACK) drop the segment
              and return.
             */
        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Rst))
        {
            if (ackOk)
            {
                SetState(TcpSocketState.Closed);
                ErrorCode = SocketError.ConnectionReset;
                throw new SocketException((int)ErrorCode);
            }

            return;
        }

        // Ignoring precedence rules

        /*This step should be reached only if the ACK is ok, or there is
              no ACK, and if the segment did not contain a RST.

              If the SYN bit is on and the security/compartment and precedence
              are acceptable then, RCV.NXT is set to SEG.SEQ+1, IRS is set to
              SEG.SEQ.  SND.UNA should be advanced to equal SEG.ACK (if there
              is an ACK), and any segments on the retransmission queue which
              are thereby acknowledged should be removed.*/

        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Syn)) // lib/tcp/input.c:352
        {
            _tcb.Rcv.Nxt = segSeq + 1;
            _tcb.Irs = segSeq;
            if (ackOk) _tcb.Snd.Una = segAck;

            UpdateRtq();
            /* If SND.UNA > ISS (our SYN has been ACKed), change the connection
                    state to ESTABLISHED, form an ACK segment

                      <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

                    and send it.  Data or controls which were queued for
                    transmission may be included.  If there are other controls or
                    text in the segment then continue processing at the sixth step
                    below where the URG bit is checked, otherwise return.
                */
            if (_tcb.Snd.Una > _tcb.Iss) // lib/tcp/input.c:371
            {
                _mss = 1460; // should be parsed
                UpdateWindow(frame.Tcp);

                ConnectionEstablished(segSeq + 1);

                Log.Debug("SYN+ACK ok, sending ACK");
                SendAck();

                // If there were any waiting processes, we could signal them now
                return;
            }
        }

        /*Otherwise enter SYN-RECEIVED, form a SYN,ACK segment

              <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

              and send it.  If there are other controls or text in the
              segment, queue them for processing after the ESTABLISHED state
              has been reached, return. */

        SetState(TcpSocketState.SynReceived);
        Log.Debug("Sending SYN+ACK");
        SendSynAck();

        // There SHOULD NOT be any data here, but
        // if there is, it should be queued for processing after we
        // get to Established
        if (frame.Tcp.Payload.Length > 0)
        {
            _earlyPayload = frame.Tcp.Payload;
        }
    }

    private void UpdateRtq() // lib/tcp/retransmission.c:152
    {
        // IEB: Continue here
        throw new NotImplementedException();
    }


    private void UpdateWindow(TcpSegment segment) // tcp_update_wnd -> lib/tcp/input.c:1062
    {
        // RFC 1122: Section 4.2.2.20 (c)
        // TCP event processing corrections
        // https://tools.ietf.org/html/rfc1122#page-94
        _tcb.Snd.Wnd = (ushort)segment.WindowSize;
        _tcb.Snd.Wl1 = (uint)segment.SequenceNumber;
        _tcb.Snd.Wl2 = (uint)segment.AcknowledgmentNumber;
    }

    /// <summary>
    /// Sequence validation
    /// </summary>
    private bool AckAcceptable(long ackNumber)
    {
        return SeqLtEq(_tcb.Snd.Una, ackNumber) && SeqLtEq(ackNumber, _tcb.Snd.Nxt);
    }
    
    // using long to save casting syntax around signed/unsigned 16&32 values
    
    private static bool SeqLt(long a, long b) => (a-b) < 0;
    private static bool SeqGt(long a, long b) => (a-b) > 0;
    private static bool SeqLtEq(long a, long b) => (a-b) <= 0;
    private static bool SeqGtEq(long a, long  b) => (a-b) >= 0;
    private static bool SeqInRange(long seq, long start, long end) => (seq - start) < (end - start);
    private static bool SeqInWindow(long seq, long start, long size) => SeqInRange(seq, start, start + size);
}

internal class ReceiveBuffer
{
    private readonly List<TcpSegment> _segments = new();

    public void Insert(TcpSegment seg)
    {
        // we will sort on read
        _segments.Add(seg);
    }

    public uint ContiguousSequence() // lib/tcp/tcp.c:361
    {
        throw new NotImplementedException();
    }
}

internal class SendBuffer
{
    private readonly object _lock = new();
    private readonly Dictionary<long, byte[]> _segments = new();
    public long Start { get; set; }

    public SendBuffer()
    {
        Start = -1;
    }

    public byte[] this[long seq]
    {
        get {
            lock (_lock)
            {
                return _segments.ContainsKey(seq) ? _segments[seq] : Array.Empty<byte>();
            }
        }
        set {
            lock (_lock)
            {
                if (Start < 0 || Start > seq) Start = seq;

                if (_segments.ContainsKey(seq))
                {
                    // accept replacement data if it is longer than previous
                    if (value.Length > _segments[seq].Length) _segments[seq] = value;
                }
                else _segments.Add(seq, value);
            }
        }
    }

    public long Count()
    {
        lock (_lock)
        {
            return _segments.Sum(s => s.Value.Length);
        }
    }

    /// <summary>
    /// Pull data from the buffer, without removing it
    /// </summary>
    public byte[] Pull(long offset, int maxSize)
    {
        
        lock (_lock)
        {
            return PullInternal(offset, maxSize);
        }
    }

    private byte[] PullInternal(long offset, int maxSize) // lib/col/seqbuf.c:39
    {
        // 1. Walk along the ordered keys until we are inside the offset requested
        // 2. Gather data in chunks until we reach the end of the buffer, or the size requested.
        //    Note: we may have overlap in the offsets we have to account for
        
        var empty = Array.Empty<byte>();
        var orderedOffsets = _segments.Keys.OrderBy(k=>k).ToList();
        if (orderedOffsets.Count < 1) return empty;
        
        int i = 0;
        for (; i < orderedOffsets.Count; i++)
        {
            var start = orderedOffsets[i];
            var chunk = _segments[start];
            var end = start + chunk.Length;

            if (start <= offset && end > offset) // found the first chunk in the range
            {
                break;
            }
        }
        if (i >= orderedOffsets.Count) return empty; // can't find any matching data

        var result = new List<byte>(maxSize);
        long remaining = maxSize;
        var loc = offset;
        while (remaining > 0 && i < orderedOffsets.Count)
        {
            var start = orderedOffsets[i];
            if (start > loc) throw new Exception("Gap in transmission stream"); // REALLY shouldn't happen
            
            var chunkOffset = loc - start;
            var chunk = _segments[start];
            var available = chunk.Length - chunkOffset;

            // check that this is a valid selection (in case of major overlap)
            if (available <= 0) { i++; continue; }
            
            var toTake = remaining < available ? remaining : available;

            result.AddRange(chunk.Skip((int)chunkOffset).Take((int)toTake));
            remaining -= toTake;
            loc += toTake;
            i++;
        }
        return result.ToArray();
    }
}