using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TransmissionControlProtocol;

/// <summary>
/// Manages a single TCP session over a virtual connection through a ChildSA tunnel.
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
/// </summary>
/// <remarks>
/// The dotnet built-in TCP/IP stack seems completely tied to using
/// the physical network, so we have to roll our own.
/// </remarks>
public class TcpSession
{
    // ### Transmission Control Block (TCB) values ###
    
    /// <summary>
    /// SEG.SEQ - segment sequence number
    /// </summary>
    private long _localSeq;
    
    /// <summary>
    /// SEG.ACK - segment acknowledgment number
    /// </summary>
    private long _remoteSeq;

    private readonly byte[] _buffer = new byte[1800];
    private static readonly Random _rnd = new();

    /// <summary>
    /// The tunnel gateway we expect to be talking to
    /// </summary>
    public IPEndPoint Gateway { get; }

    /// <summary>
    /// The tunnel session we are connected to (used for sending replies)
    /// </summary>
    private readonly ChildSa _transport;

    private readonly SenderPort _transportKey;

    /// <summary>
    /// Socket used to communicate with web app
    /// </summary>
    private Socket? _socks;

    /// <summary>
    /// Current session state
    /// </summary>
    public TcpSocketState State { get; set; }

    /// <summary>
    /// Time since last packets send or received.
    /// Only starts ticking when first packets transmitted.
    /// </summary>
    public Stopwatch LastContact { get; set; }

    /// <summary>
    /// Address of remote side
    /// </summary>
    public byte[] RemoteAddress { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Port declared by remote side
    /// </summary>
    public int RemotePort { get; private set; }

    /// <summary>
    /// Address requested for this session
    /// </summary>
    public byte[] LocalAddress { get; private set; } = Array.Empty<byte>();

    /// <summary>
    /// Local port requested for this session
    /// </summary>
    public int LocalPort { get; private set; }
    
    
    private readonly Thread _backflowThread;
    private volatile bool _running;
    private int _port;

    public TcpSession(ChildSa transport, IPEndPoint gateway, SenderPort transportKey)
    {
        _transport = transport;
        _transportKey = transportKey;
        Gateway = gateway;
        
        _backflowThread = new Thread(BackflowLoop){IsBackground = true};
        
        State = TcpSocketState.Closed;
        LastContact = new Stopwatch();
    }

    /// <summary>
    /// Initiate a connection from a first incoming packet
    /// </summary>
    public bool Start(IpV4Packet ipv4)
    {
        if (_socks is null)
        {
            _socks = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Raw);
            _socks.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            _socks.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            //_socks.Connect(IPAddress.Loopback, Settings.WebAppPort);
            try
            {
                _port = (_socks.LocalEndPoint as IPEndPoint)?.Port ?? -1;
                
                Log.Critical($"Connected to web app. Local port={_port}");
            }
            catch (Exception ex)
            {
                Log.Critical("COULDN'T READ BINDING"+ex);
            }
        }
        
        
        // capture identity (we will write it back when we tunnel the reply)
        ByteSerialiser.FromBytes<TcpSegment>(ipv4.Payload, out var tcp);
        LocalAddress = ipv4.Destination.Value;
        LocalPort = tcp.DestinationPort;
        RemotePort = tcp.SourcePort;
        RemoteAddress = ipv4.Source.Value;

        Log.Critical($"Captured session identity: {ipv4.Source.AsString}:{tcp.SourcePort} -> {ipv4.Destination.AsString}:{tcp.DestinationPort}");

        _running= true;
        _backflowThread.Start();
        
        LastContact.Start(); // start counting. This gets reset every time we get another message
        
        _socks.Send(new byte[100]); // test

        // TODO: try nothing here and see if we still connect
        RedirectPacket(ipv4);
        return true;

        /*
        AssertState(TcpSocketState.Closed);
        Log.Debug("TCP session initiation");

        // ready to act as a server
        _localSeq = _rnd.Next(100, 65000); // random sequence for our side
        State = TcpSocketState.Listen;

        var ok = HandleMessage(ipv4, out var tcp);
        if (!ok)
        {
            Log.Debug("TCP session initiation failed");
            State = TcpSocketState.Closed;
            return false;
        }

        LastContact.Start(); // start counting. This gets reset every time we get another message

        // capture identity
        LocalAddress = ipv4.Destination.Value;
        LocalPort = tcp.DestinationPort;
        RemotePort = tcp.SourcePort;
        RemoteAddress = ipv4.Source.Value;

        Log.Debug("TCP session initiation completed:" +
                  $" remote={Bit.ToIpAddressString(RemoteAddress)}:{RemotePort}," +
                  $" local={Bit.ToIpAddressString(LocalAddress)}:{LocalPort}");

        return true;
        */
    }

    private void RedirectPacket(IpV4Packet ipv4)
    {
        var dstPre = ipv4.Destination;
        var srcPre = ipv4.Source;
        
        ipv4.Destination = IpV4Address.Localhost;
        ipv4.Source = IpV4Address.Localhost;

        _ = ByteSerialiser.FromBytes<TcpSegment>(ipv4.Payload, out var tcp);
        
        var dstPPre = tcp.DestinationPort;
        var srcPPre = tcp.SourcePort;
        
        tcp.DestinationPort = Settings.WebAppPort;
        tcp.SourcePort = _port;

        tcp.UpdateChecksum(ipv4.Source.Value, ipv4.Destination.Value);

        ipv4.Payload = ByteSerialiser.ToBytes(tcp);
        ipv4.UpdateChecksum();

        var raw = ByteSerialiser.ToBytes(ipv4);
        
        Log.Info($">>>>From web-app: {srcPre.AsString}:{srcPPre} -> {dstPre.AsString}:{dstPPre}" +
                 $"\r\n>>>>To tunnel:    {ipv4.Source.AsString}:{tcp.SourcePort} -> {ipv4.Destination.AsString}:{tcp.DestinationPort}");

        Log.Debug(Bit.Describe("raw transfer", raw));
        Log.Debug(Bit.SafeString(raw));

        var written = _socks?.Send(raw) ?? 0;
        //var written = _socks?.SendTo(raw, new IPEndPoint(IPAddress.Loopback, Settings.WebAppPort)) ?? 0;
        Log.Info($"Send {written} bytes to app from {raw.Length} bytes in payload");
    }

    /// <summary>
    /// Continue a session with a packet from the remote
    /// </summary>
    public void Accept(IpV4Packet ipv4)
    {
        LastContact.Restart(); // back to zero, keep counting
        RedirectPacket(ipv4);
        
        //HandleMessage(ipv4, out _);
    }
    
    /// <summary>
    /// Read payload of an IPv4 packet to determine the source address
    /// and sender port. This is used to uniquely key sessions.
    /// </summary>
    public static SenderPort ReadSenderAndPort(IpV4Packet message)
    {
        var ok = ByteSerialiser.FromBytes<TcpSegment>(message.Payload, out var tcpSeg);

        if (!ok) return new SenderPort(Array.Empty<byte>(), 0);

        return new SenderPort(message.Source.Value, tcpSeg.DestinationPort);
    }

    public void Close()
    {
        _running = false;
        _socks?.Close();
        _socks?.Dispose();
        
        // TODO: shut down this connection
    }

    /// <summary>
    /// Feed incoming message through the TCP state machine
    /// </summary>
    private bool HandleMessage(IpV4Packet ipv4, out TcpSegment tcp)
    {
        // read the TCP segment
        var ok = ByteSerialiser.FromBytes(ipv4.Payload, out tcp);
        if (!ok)
        {
            Log.Warn("TCP payload did not parse");
            Log.Debug(Bit.Describe("ipv4 payload", ipv4.Payload));
            return false;
        }
        
        // TODO: double check that incoming is for the session we expect?
        

        switch (State)
        {
            case TcpSocketState.Closed:
                throw new Exception("Tried to communicate with a closed connection");

            case TcpSocketState.Listen: // Expect to receive a SYN message and move to SynReceived
            {
                if (tcp.Flags != TcpSegmentFlags.Syn) throw new Exception($"Invalid flags. Local state={State.ToString()}, request flags={tcp.Flags.ToString()}");
                _remoteSeq = tcp.SequenceNumber + 1;

                var replyPkt = new TcpSegment
                {
                    SourcePort = tcp.DestinationPort,
                    DestinationPort = tcp.SourcePort,
                    SequenceNumber = _localSeq,
                    AcknowledgmentNumber = _remoteSeq,
                    DataOffset = 5,
                    Reserved = 0,
                    Flags = TcpSegmentFlags.SynAck,
                    WindowSize = tcp.WindowSize,
                    Options = Array.Empty<byte>(),
                    Payload = Array.Empty<byte>()
                };
                Reply(sender: ipv4, message: replyPkt);
                State = TcpSocketState.SynReceived; // other side should switch to Established.

                break;
            }
            case TcpSocketState.SynReceived: // Expect to receive an ACK message and move to Established
            {
                if (tcp.Flags != TcpSegmentFlags.Ack) Log.Warn($"Invalid flags. Local state={State.ToString()}, request flags={tcp.Flags.ToString()}");

                if (tcp.SequenceNumber != _remoteSeq) Log.Warn($"Initial SYNC: Request out of sequence: Expected {_remoteSeq}, got {tcp.SequenceNumber}");
                if (tcp.AcknowledgmentNumber != _localSeq) Log.Warn($"Initial SYNC: Acknowledgement out of sequence: Expected {_localSeq}, got {tcp.AcknowledgmentNumber}");

                // Open our connection to the app
                if (_socks is null)
                {
                    _socks = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Tcp);
                    _socks.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                    _socks.Connect(IPAddress.Loopback, Settings.WebAppPort);
                }

                // Set new state
                State = TcpSocketState.Established;

                break;
            }
            case TcpSocketState.Established:
            {
                // We should either get an empty ACK message (end of handshake)
                // OR an ACK message with data (streaming)

                if (tcp.Flags.HasFlag(TcpSegmentFlags.Rst))
                {
                    Log.Info($"Other side wants to close? flags={tcp.Flags.ToString()}");
                    State = TcpSocketState.FinWait1;
                    // TODO: clean termination
                    _transport.EndSession(_transportKey);
                    
                    break;
                }
                if (tcp.Flags == TcpSegmentFlags.Ack && tcp.Payload.Length < 1)
                {
                    Log.Info($"Handshake complete. Connected to {ipv4.Source.AsString}:{tcp.SourcePort}");
                    break;
                }
                
                if (tcp.SequenceNumber != _remoteSeq) Log.Warn($"Established request out of sequence: Expected {_remoteSeq}, got {tcp.SequenceNumber}");
                if (tcp.AcknowledgmentNumber != _localSeq) Log.Warn($"Established acknowledgement out of sequence: Expected {_localSeq}, got {tcp.AcknowledgmentNumber}");


                _remoteSeq++;
                
                Log.Info($"Tcp packet. Flags={tcp.Flags.ToString()}, Data length={tcp.Payload.Length}, Seq={tcp.SequenceNumber}");

                
                
                if (tcp.Payload.Length > 0)
                {
                    Log.Warn("Would write to web app?");
                    Log.Info($"{Encoding.UTF8.GetString(tcp.Payload)} - {Bit.Describe("in", ipv4.Payload)}");
                    
                    var newIpv4 = new IpV4Packet
                    {
                        Version = IpV4Version.Version4,
                        HeaderLength = 5,
                        ServiceType = 0,
                        TotalLength = 20,
                        PacketId = 0,
                        Flags = IpV4HeaderFlags.DontFragment,
                        FragmentIndex = 0,
                        Ttl = 64,
                        Protocol = IpV4Protocol.TCP,
                        Checksum = 0,
                        Source = IpV4Address.Localhost,
                        Destination = IpV4Address.Localhost,
                        Options = new byte[] { },
                        Payload = new byte[] { }
                    };
                    newIpv4.UpdateChecksum();
                    var test = ByteSerialiser.ToBytes(newIpv4);
                    
                    var written = _socks?.Send(test) ?? 0;
                    Log.Info($"Send {written} bytes to app from {test} bytes in payload");
                }
                
                
                
                
                // IEB: This is picking up MY outgoing messages?
                // IEB: OR, is this reading bits of my SSH session!?
                // pump data available
                ReadFromWebApp();
                break;
            }

            // TODO: manage these states
            case TcpSocketState.FinWait1:
            case TcpSocketState.FinWait2:
            case TcpSocketState.CloseWait:
            case TcpSocketState.Closing:
            case TcpSocketState.LastAck:
            case TcpSocketState.TimeWait:
            case TcpSocketState.SynSent:
                Log.Info($"Immediate end of session from state: {State.ToString()}");
                _transport.EndSession(_transportKey);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        Log.Warn($"From {ipv4.Source.AsString}:{tcp.SourcePort} to {ipv4.Destination.AsString}:{tcp.DestinationPort}");
        Log.Warn($"Flags: {tcp.Flags.ToString()}, seq={tcp.SequenceNumber}, ack={tcp.AcknowledgmentNumber}");


        //var reply = new IpV4Packet();
        //_transport.Send(reply, Gateway);
        return true;
    }

    

    private void BackflowLoop()
    {
        Log.Info("Backflow started");
        while (_running)
        {
            try
            {
                ReadFromWebApp();
            }
            catch (Exception ex)
            {
                Log.Error("Error in TCP session backflow loop", ex);
            }
        }
        Log.Info("Backflow ended");
    }
    
    
    /// <summary>
    /// Read any data back from app to tunnel
    /// </summary>
    private void ReadFromWebApp()
    {
        var available = _socks?.Available ?? 0;
        
        if (available < 1) Thread.Sleep(10);
        
        while (available > 0)
        {
            Log.Info($"{available} bytes on socket");
            var read = _socks!.Receive(_buffer);
            available = _socks?.Available ?? 0;

            ByteSerialiser.FromBytes<IpV4Packet>(_buffer.Take(read), out var ipv4);
            if (!ipv4.Destination.IsLocalhost)
            {
                Log.Debug($"Noise {ipv4.Source.AsString} -> {ipv4.Destination.AsString}");
            }
            else
            {
                Log.Info("Directing packet back through tunnel");
                
                Log.Debug(TypeDescriber.Describe(ipv4));
                
                var dstPre = ipv4.Destination;
                var srcPre = ipv4.Source;

                ipv4.Destination = new IpV4Address(RemoteAddress);
                ipv4.Source = new IpV4Address(LocalAddress);
                
                if (ipv4.Payload.Length > 0)
                {
                    ByteSerialiser.FromBytes<TcpSegment>(ipv4.Payload, out var tcp);
                    Log.Debug($">>>>>  Inner message >>>>>  {Bit.SafeString(tcp.Payload)}");

                    var dstPPre = tcp.DestinationPort;
                    var srcPPre = tcp.SourcePort;
                    
                    tcp.DestinationPort = RemotePort;
                    tcp.SourcePort = LocalPort;

                    tcp.UpdateChecksum(ipv4.Source.Value, ipv4.Destination.Value);

                    Log.Info($"\r\n>>>>From web-app: {srcPre.AsString}:{srcPPre} -> {dstPre.AsString}:{dstPPre}" +
                             $"\r\n>>>>To tunnel:    {ipv4.Source.AsString}:{tcp.SourcePort} -> {ipv4.Destination.AsString}:{tcp.DestinationPort}");
                    
                    ipv4.Payload = ByteSerialiser.ToBytes(tcp);
                }

                ipv4.UpdateChecksum();
                
                _transport.Send(ipv4, Gateway);

                //var data = Encoding.ASCII.GetBytes(msgStr);
                /*
                var replyPkt = new TcpSegment
                {
                    SourcePort = LocalPort,
                    DestinationPort = RemotePort,
                    SequenceNumber = _localSeq++,
                    AcknowledgmentNumber = _remoteSeq,
                    DataOffset = 5,
                    Reserved = 0,
                    Flags = available > 0 ? TcpSegmentFlags.None : (TcpSegmentFlags.Ack | TcpSegmentFlags.Psh),
                    WindowSize = tcp.WindowSize,
                    Options = Array.Empty<byte>(),
                    Payload = data
                };
                Reply(sender: ipv4, message: replyPkt);
                */
            }
        }
    }

    /// <summary>
    /// Send a reply through the connected gateway, back to original sender,
    /// with a new message. This increments local sequence number.
    /// </summary>
    private void Reply(IpV4Packet sender, TcpSegment message)
    {
        
        // Set message checksum
        message.UpdateChecksum(sender.Destination.Value, sender.Source.Value);
        Log.Info($"Tcp checksum={message.Checksum:x4} (" +
                  $"dest={Bit.HexString(sender.Destination.Value)}, src={Bit.HexString(sender.Source.Value)}, proto={(byte)IpV4Protocol.TCP}, " +
                  $"destPort={message.DestinationPort}, srcPort={message.SourcePort}, " +
                  $"seq={message.SequenceNumber}, ack#={message.AcknowledgmentNumber})");
        var tcpPayload = ByteSerialiser.ToBytes(message);
        
        // prepare container
        var reply = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + tcpPayload.Length,
            PacketId = _rnd.Next(10, 32700),
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.TCP,
            Checksum = 0,
            Source = sender.Destination,
            Destination = sender.Source,
            Options = Array.Empty<byte>(),
            Payload = tcpPayload
        };
        
        _localSeq++;
        
        reply.UpdateChecksum();
        Log.Info($"IPv4 checksum={reply.Checksum:x4}");
        
        _transport.Send(reply, Gateway);
    }


    private void AssertState(TcpSocketState expected)
    {
        if (State != expected) throw new Exception($"Invalid state. Expected {expected.ToString()}, got {State.ToString()}");
    }
}