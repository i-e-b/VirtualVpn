// ReSharper disable BuiltInTypeReferenceStyle

using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
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
/// Derived from https://github.com/frebib/netstack.git
/// Adapted to work non-blocking with an external event pump, and against virtual devices.
/// </remarks>
public class TcpSocket
{
    /// <summary>
    /// .Net standard codes for socket errors
    /// </summary>
    public SocketError ErrorCode { get; set; }

    /// <summary>
    /// State of the socket interface
    /// </summary>
    public TcpSocketState State => _state;
    
    /// <summary>
    /// Amount of data that is either waiting to
    /// be sent, or waiting for an acknowledgment.
    /// When this reaches zero after starting to
    /// send data, then all data has been transmitted
    /// AND received.
    /// </summary>
    public long BytesOfSendDataWaiting => _sendBuffer.Count();
    
    /// <summary>
    /// Amount of data that has been queued for reading.
    /// This may be more than the total size of the stream if
    /// the remote side is sending overlaps
    /// </summary>
    public long BytesOfReadDataWaiting => _receiveQueue.EntireSize;

    /// <summary>
    /// Returns true if we processed an in-sequence FIN message,
    /// indicating that all data is here and received.
    /// </summary>
    public bool ReadDataComplete => _receiveQueue.IsComplete;

    #region Private state

    /// <summary> Tunnel interface (used instead of sockets) </summary>
    private readonly ITcpAdaptor _adaptor;

    /// <summary> State of this 'socket' </summary>
    private TcpSocketState _state;

    /// <summary> State machine variables </summary>
    private readonly TransmissionControlBlock _tcb;

    /// <summary> Maximum Segment Size </summary>
    private UInt16 _mss;

    /// <summary> Blocks of sent data, in case of retransmission </summary>
    private readonly SendBuffer _sendBuffer = new();

    /// <summary> Sorted list of incoming TCP packets </summary>
    private readonly ReceiveBuffer _receiveQueue = new();

    /// <summary> Sequence numbers of unacknowledged segments.</summary>
    private readonly SegmentAckList _unAckedSegments = new();

    /// <summary> Retransmit Time-Out (RTO) value (calculated from _rtt) </summary>
    private TimeSpan _rto;

    private TimeSpan _sRtt, _rttVar; // Round-trip time values

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
    private TcpSegment _earlyPayload = new();

    /// <summary>
    /// Rate limiting factor
    /// </summary>
    private int _backoff;

    /// <summary>
    /// True if we are the active party (requester, initiator, client)
    /// False if we are the passive (listener, receiver, server)
    /// </summary>
    private bool _isActive;
    
    /// <summary>
    /// Retransmit event timer. Null if all messages are acknowledged.
    /// </summary>
    private TcpTimedEvent? _rtoEvent; // most recent retransmit timeout, if any

    /// <summary>
    /// Monotonic TCP waiting timer. Null if nothing is waiting.
    /// </summary>
    private readonly TcpTimedEvent? _timeWait;
    
    private readonly AutoResetEvent _sendWait;
    private readonly AutoResetEvent _readWait;

    #endregion

    /// <summary>
    /// Create a new virtual TCP socket interface for the VPN tunnel
    /// </summary>
    public TcpSocket(ITcpAdaptor adaptor)
    {
        ErrorCode = SocketError.Success;

        _adaptor = adaptor;
        _isActive = true; // flipped if `Listen()` is called

        _state = TcpSocketState.Closed;
        _mss = TcpDefaults.DefaultMss;

        _rtoEvent = null;
        _timeWait = null;

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
        // check for any timers or queues that need driving through this socket
        
        SendIfPossible();
        _rtoEvent?.TriggerIfExpired();
        _timeWait?.TriggerIfExpired();
    }

    /// <summary>
    /// Process incoming TCP segment and IPv4 wrapper.
    /// You must supply any incoming packets to this function.
    /// </summary>
    public void FeedIncomingPacket(TcpSegment segment, IpV4Packet wrapper)
    {
        ReceiveWithIpv4(segment, wrapper);
    }

    /// <summary>
    /// Set this socket to the listen state
    /// </summary>
    public void Listen()
    {
        _isActive = false;
        SetState(TcpSocketState.Listen);
    }

    /// <summary>
    /// Start a connection to a remote machine.
    /// This will return before the connection
    /// is established. You should pump events
    /// and wait error code to change from the
    /// success status, or the state to become
    /// established.
    /// </summary>
    public void StartConnect(IpV4Address destinationAddress, ushort destinationPort) // lib/tcp/user.c:21
    {
        lock (_lock)
        {
            _route.RemoteAddress = destinationAddress.Copy();
            _route.RemotePort = destinationPort;

            // Check we are in a valid state
            switch (_state)
            {
                case TcpSocketState.Established:
                case TcpSocketState.FinWait1:
                case TcpSocketState.FinWait2:
                case TcpSocketState.LastAck:
                case TcpSocketState.Closing:
                case TcpSocketState.CloseWait:
                    ErrorCode = SocketError.IsConnected;
                    throw new SocketException((int)ErrorCode);

                case TcpSocketState.SynSent:
                case TcpSocketState.SynReceived:
                    ErrorCode = SocketError.AlreadyInProgress;
                    throw new SocketException((int)ErrorCode);

                case TcpSocketState.Closed:
                case TcpSocketState.Listen:
                case TcpSocketState.TimeWait:
                    Log.Debug("Starting connection process");
                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            // Set up initial TCB variables
            var iss = NewTcpSequence();
            _tcb.Iss = iss;
            _tcb.Snd.Una = iss;
            _tcb.Snd.Nxt = iss + 1;
            _tcb.Rcv.Wnd = UInt16.MaxValue;

            // Ensure the state is SynSent BEFORE calling SendSyn() so that
            // the correct retransmit timeout function is used
            SetState(TcpSocketState.SynSent);

            SendSyn();

            // Normally, a socket connection would block here,
            // but we are using a caller-poll convention
            // so we just return and expect the caller to
            // check the state periodically until there is
            // an error code or the state becomes Established.
        }
    }

    /// <summary>
    /// Begin the process of closing a connection.
    /// This will return before the connection is
    /// closed. You should call EventPump() until
    /// the error code changes from success state
    /// or the state becomes closed.
    /// </summary>
    public void StartClose() // lib/tcp/user.c:380
    {
        lock (_lock)
        {
            switch (_state)
            {
                case TcpSocketState.Listen:
                    SetState(TcpSocketState.Closed);
                    break;
                
                case TcpSocketState.SynSent:
                    break;
                
                case TcpSocketState.SynReceived: // Note: should check for any pending data to send, but not handled here
                case TcpSocketState.Established:
                    SetState(TcpSocketState.FinWait1);
                    //SendAckFin(); // source has this, but refs say just FIN if we are client
                    if (_isActive) SendFin();
                    else SendAckFin();

                    break;
                
                case TcpSocketState.CloseWait: // Note: should check for any pending data to send, but not handled here. See https://tools.ietf.org/html/rfc1122#page-93
                    SetState(TcpSocketState.LastAck);
                    SendAckFin();
                    break;
                
                case TcpSocketState.Closing:
                case TcpSocketState.LastAck:
                case TcpSocketState.TimeWait:
                    ErrorCode = SocketError.AlreadyInProgress;
                    break;
                
                case TcpSocketState.Closed:
                    ErrorCode = SocketError.NotConnected;
                    break;
                
                case TcpSocketState.FinWait1:
                case TcpSocketState.FinWait2:
                    break;
                
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }
    }

    /// <summary>
    /// Begin sending buffer data.
    /// This will return before all the data is sent.
    /// You should call EventPump() until the error
    /// code changes or SendBufferLength becomes zero.
    /// </summary>
    public void SendData(byte[] buffer, int offset, int length) // lib/tcp/user.c:122
    {
        if (!ValidStateForSend()) throw new Exception($"Socket is not ready for sending. State={_state.ToString()}");

        lock (_lock)
        {
            if (!_sendBuffer.SequenceIsSet())
            {
                Log.Debug($"Starting send stream at sequence {_tcb.Snd.Nxt} for {length} bytes");
                _sendBuffer.SetStartSequence(_tcb.Snd.Nxt);
            }
            
            _sendBuffer.Write(buffer, offset, length);
        }

        throw new NotImplementedException();
    }
    
    /// <summary>
    /// Read data from the incoming data buffer.
    /// This does not block, and may not return all data
    /// if transmission is not complete.
    /// </summary>
    /// <returns>Actual bytes copied</returns>
    public int ReadData(byte[] buffer, int offset, int length)
    {
        lock (_lock)
        {
            return _receiveQueue.ReadOutAndUpdate(buffer, offset, length);
        }
    }

    #region private
    

    /// <summary>
    /// Process an incoming tcp segment given an IPv4 wrapper
    /// </summary>
    private void ReceiveWithIpv4(TcpSegment segment, IpV4Packet wrapper) // lib/tcp/tcp.c:128
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
    /// Send next chunk of data that will fit in the destination's
    /// receive window. This might be zero
    /// </summary>
    private void SendIfPossible() // lib/tcp/user.c:141
    {
        lock (_lock)
        {
            if (!ValidStateForSend()) return; // can't send
            if (_sendBuffer.Count() < 1) return; // nothing to send

            long inflight = 0;
            foreach (var segment in _unAckedSegments)
            {
                inflight += segment.Length;
            }

            long space = Max(0, _tcb.Snd.Wnd - inflight);
            if (space <= 0)
            {
                Log.Info("No space in send window. Waiting for an incoming ACK");
                return;
            }

            var total = _sendBuffer.Count();
            var sent = SendData(_tcb.Snd.Nxt, (int)space, TcpSegmentFlags.None);
            Log.Debug($"Sent {sent} bytes, {total - sent} remaining");
        }
    }
    
    private bool ValidStateForSend() // lib/tcp/user.c:102
    {
        switch (_state)
        {
            case TcpSocketState.Established:
            case TcpSocketState.CloseWait:
                return true;
            
            case TcpSocketState.Closed:
            case TcpSocketState.Listen:
            case TcpSocketState.SynSent:
            case TcpSocketState.SynReceived:
                ErrorCode = SocketError.NotConnected;
                return false;
                
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            case TcpSocketState.TimeWait:
                ErrorCode = SocketError.Shutdown;
                return false;
            
            default:
                throw new ArgumentOutOfRangeException();
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
        var iss = NewTcpSequence(); // initial sequence on our side
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
    private void SendFin() => SendEmpty(_tcb.Snd.Nxt++, _tcb.Rcv.Nxt, TcpSegmentFlags.Fin);
    private void SendRst(long sequence) => SendEmpty(sequence, 0, TcpSegmentFlags.Rst);
    private void SendRstAck(long sequence, long ackNumber) => SendEmpty(sequence, ackNumber, TcpSegmentFlags.Rst | TcpSegmentFlags.Ack);

    private void SendEmpty(long sequence, long ackNumber, TcpSegmentFlags controlFlags) // include/netstack/tcp/tcp.h:473, lib/tcp/output.c:100
    {
        // This should go through the tunnel. We don't need to do any routing ourselves.

        // lib/tcp/output.c:117
        var seg = new TcpSegment
        {
            // lib/tcp/output.c:256
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
        
        seg.UpdateChecksum(_route.LocalAddress.Value, _route.RemoteAddress.Value);

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
        _unAckedSegments.Add(new TcpTimedSequentialData
        {
            Sequence = sequence,
            Flags = flags,
        });

        // Advance SND.NXT past this segment
        _tcb.Snd.Nxt += (uint)dataLength;
    }

    private void StartRto(int dataLength, TcpSegmentFlags flags) // lib/tcp/retransmission.c:46
    {
        // This is a highly simplified retry clock.
        _rtoEvent = new TcpTimedEvent
        {
            Sequence = _tcb.Snd.Nxt,
            Length = dataLength,
            Flags = flags,
            Action = RetransmissionTimeout, // Source had this as null. I think it should be 'tcp_retransmission_timeout' ( lib/tcp/retransmission.c:68 )
            Timeout = TcpDefaults.InitialRto
        };
    }

    private void RetransmissionTimeout(TcpTimedEvent evt) // lib/tcp/retransmission.c:68
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
            if (waiting is null)
            {
                _rtoEvent = null;
                return;
            }

            var data = _sendBuffer[waiting.Sequence];
            var next = new TcpTimedEvent
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
    /// <returns>Number of bytes sent</returns>
    private int SendData(uint sequence, int size, TcpSegmentFlags flags) // lib/tcp/output.c:135
    {
        // lib/tcp/output.c:153
        var ackN = _tcb.Rcv.Nxt;
        flags |= TcpSegmentFlags.Ack;

        var bytesAvailable = _sendBuffer.Count();
        if (bytesAvailable < 1)
        {
            ErrorCode = SocketError.NoData;
            Log.Error("Call to SendData, with no data in outgoing buffer");
            return 0;
        }

        var seg = new TcpSegment
        {
            // lib/tcp/output.c:161
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
            return 0;
        }

        Send(seg, _route); // lib/tcp/output.c:212
        return seg.Payload.Length;
    }

    /// <summary>
    /// Try to start a connection.
    /// </summary>
    private void SendSyn() // lib/tcp/output.c:47
    {
        // This should go through the tunnel.
        // Syn has a lot of rate logic

        var seg = new TcpSegment
        {
            // lib/tcp/output.c:256
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

            _rtoEvent = new TcpTimedEvent
            {
                // lib/tcp/output.c:79
                Sequence = _tcb.Iss,
                Length = 0,
                Flags = TcpSegmentFlags.Syn,
                Action = SynRetransmissionTimeout,
                Timeout = TcpDefaults.InitialRto
            };
        }

        Send(seg, _route);
    }

    private void SynRetransmissionTimeout(TcpTimedEvent eventData) // lib/tcp/retransmission.c:10
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
        if (frame.Tcp.Flags.FlagsClear(TcpSegmentFlags.Ack))
        {
            // Handle the case of a FIN with no ACK
            // The RFC and other references are unclear, so we will try to handle
            // FIN or FIN+ACK
            if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Fin))
            {
                HandleFinFlag(segSeq);
            }
            return;
        }

        if (HandleIncomingAckFlag(frame, ackOk, segSeq, segAck)) return;

        if (HandleShutdownAcks(inOrder)) return;

        // Ignoring urgent flag

        // Handle actual input data
        ProcessSegmentData(frame, segLen, inOrder);

        // Filter FIN flag
        if (DropIfFinFlagsInvalid(frame, segSeq)) return;

        if (frame.Tcp.Flags.FlagsSet(TcpSegmentFlags.Fin))
        {
            HandleFinFlag(segSeq);
        }

        Log.Debug("End of receive");
    }

    private void HandleFinFlag(uint segSeq)
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
        _receiveQueue.SetComplete();

        Log.Debug("End of stream. Sending ACK");
        _tcb.Rcv.Nxt = segSeq + 1;
        SendAck();
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
                _tcb.Rcv.Nxt = _receiveQueue.ContiguousSequence(_tcb.Rcv.Nxt);
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
        //return _tcb.Snd.Una == (_sendBuffer.Start + _sendBuffer.Count() + 1); // IEB: Not sure if this works when no data has been sent
        return _tcb.Snd.Una == (_sendBuffer.Start + _sendBuffer.Count());
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
        
        if (_earlyPayload.Payload.Length > 0) // Not sure if I should support this
        {
            Log.Warn($"Connection had {_earlyPayload.Payload.Length} bytes of early payload, will be added at seq={_earlyPayload.SequenceNumber}; current seq={segSeq}");
            _receiveQueue.Insert(_earlyPayload);
            _earlyPayload = new TcpSegment();
        }
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
    private static long Max(long a, long  b) => a > b ? a : b;

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
            _earlyPayload = frame.Tcp;
        }
    }

    private void UpdateRtq() // lib/tcp/retransmission.c:152
    {
        lock (_lock)
        {
            var unack = _tcb.Snd.Una;
            switch (_state)
            {
                case TcpSocketState.SynSent:
                    break;

                default:
                    if (FinWasAcked()) // Ensure we don't try to consume the non-existent ACK byte for our FIN
                    {
                        unack--;
                    }

                    // Release all acknowledged bytes from send buffer
                    _sendBuffer.ConsumeTo(unack);
                    break;
            }

            Log.Debug($"Checking {_unAckedSegments.Count} unacknowledged segments"); // lib/tcp/retransmission.c:172

            TcpTimedSequentialData? latest = null;
            foreach (var data in _unAckedSegments) // lib/tcp/retransmission.c:174
            {
                var iss = _tcb.Iss;
                var end = data.Sequence + data.Length - 1;

                if (SeqGt(_tcb.Snd.Una, end))
                {
                    Log.Debug($"Removing acknowledged segment {data.Sequence - iss}..{end - iss}");

                    // Store the latest ACKed segment for updating the rtt
                    // Retransmitted segments should NOT be used for rtt calculation
                    if (_backoff < 1) latest = data;

                    _unAckedSegments.Remove(data);
                }
            }

            if (latest is not null && latest.Sequence != 0 && latest.Length != 0) // lib/tcp/retransmission.c:195
            {
                // Update the round-trip time with the latest ACK received
                var iss = _tcb.Iss;
                var end = latest.Sequence + latest.Length - 1;
                Log.Debug($"Updating RTT with segment {latest.Sequence - iss}..{end - iss}");
                UpdateRtt(latest);
            }

            // stop RTO is there are no unacknowledged segments left
            if (_unAckedSegments.Count < 1)
            {
                Log.Debug("No more unacknowledged segments. Ending retry time-out.");
                _rtoEvent = null;
            }
        }
    }

    private void UpdateRtt(TcpTimedSequentialData acked) // lib/tcp/retransmission.c:225
    {
        acked.Clock.Stop();
        Log.Debug($"Round trip: {acked.Clock}");

        // RFC 6298: Computing TCP Retransmission Timer
        // https://tools.ietf.org/html/rfc6298

        if (_sRtt.Ticks == 0) // make initial measurement
        {
            _sRtt = acked.Clock.Elapsed;
            _rttVar = acked.Clock.Elapsed.Divide(2);
        }
        else
        {
            const double beta = 0.25;
            const double alpha = 0.125;
            double r = acked.Clock.ElapsedTicks;
            double rttVar = _rttVar.Ticks;
            double sRtt = _sRtt.Ticks;

            rttVar = (1 - beta) * rttVar + beta * Math.Abs(sRtt - r);
            sRtt = (1 - alpha) * sRtt + alpha * r;

            _sRtt = TimeSpan.FromTicks((long)sRtt);
            _rttVar = TimeSpan.FromTicks((long)rttVar);
        }

        double rto = _sRtt.Ticks + (_rttVar.Ticks * 4.0);
        rto = Math.Max(rto, TcpDefaults.MinimumRto.Ticks);
        _rto = TimeSpan.FromTicks((long)rto);

        Log.Debug($"RTO <- {_rto}");
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

    private static bool SeqLt(long a, long b) => (a - b) < 0;
    private static bool SeqGt(long a, long b) => (a - b) > 0;
    private static bool SeqLtEq(long a, long b) => (a - b) <= 0;
    private static bool SeqInRange(long seq, long start, long end) => (seq - start) < (end - start);
    private static bool SeqInWindow(long seq, long start, long size) => SeqInRange(seq, start, start + size);

    #endregion // private
}