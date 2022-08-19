using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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
    /// <summary>
    /// The low-level socket we use to talk to our app
    /// </summary>
    private readonly Socket _comms;

    private readonly Stopwatch _stopwatch = new ();
    
    private readonly Thread _listenerThread;
    private volatile bool _running;
    
    /// <summary>
    /// Time since last packets sent or received.
    /// Returns zero if the session has never started
    /// </summary>
    public TimeSpan LastContact => _stopwatch.IsRunning ? _stopwatch.Elapsed : TimeSpan.Zero;

    /// <summary>
    /// The tunnel gateway we expect to be talking to
    /// </summary>
    public IPEndPoint Gateway { get; }

    /// <summary>
    /// The tunnel session we are connected to (used for sending replies)
    /// </summary>
    private readonly ChildSa _transport;

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

    public TcpSession(ChildSa transport, IPEndPoint gateway)
    {
        _transport = transport;
        Gateway = gateway;
        
        _listenerThread = new Thread(ListenerThreadLoop){IsBackground = true};
        _running = false;
        
        
        
        // IP localhost > localhost: ICMP localhost udp port 5223 unreachable, length 76
        //_comms = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.IP) { Blocking = true };
        
        //_comms = new Socket(AddressFamily.Packet, SocketType.Raw, ProtocolType.Raw) { Blocking = true }; // this is what I want, but it gives "invalid argument"
        //_comms = new Socket((AddressFamily)17, SocketType.Dgram, (ProtocolType)0x0004) { Blocking = true }; // https://github.com/dotnet/runtime/issues/24076
        
        // From https://github.com/dotnet/runtime/issues/26416
        Int16 protocol = 0x800; // IP.
        _comms = new Socket(AddressFamily.Packet, SocketType.Raw, (ProtocolType)IPAddress.HostToNetworkOrder(protocol));

    }

    /// <summary>
    /// Initiate a connection from a first incoming packet
    /// </summary>
    public bool Start(IpV4Packet ipv4)
    {
        Log.Debug("TCP session initiation");
        
        // start listening thread
        _running = true;
        //_comms.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listenerThread.Start();

        var ok = HandleMessage(ipv4, out var tcp);
        if (!ok)
        {
            Log.Debug("TCP session initiation failed");
            return false;
        }

        // capture identity
        LocalAddress = ipv4.Destination.Value;
        LocalPort = tcp.DestinationPort;
        RemotePort = tcp.SourcePort;
        RemoteAddress = ipv4.Source.Value;
        

        Log.Debug("TCP session initiation completed:" +
                  $" remote={Bit.ToIpAddressString(RemoteAddress)}:{RemotePort}," +
                  $" local={Bit.ToIpAddressString(LocalAddress)}:{LocalPort}");

        return true;
    }

    /// <summary>
    /// Continue a session with a packet from the remote
    /// </summary>
    public void Accept(IpV4Packet ipv4)
    {
        HandleMessage(ipv4, out _);
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

    private void ListenerThreadLoop()
    {
        var buffer = new byte[66000]; // a bit larger than the maximum TCP packet
        _comms.Blocking = true; // wait for data


        while (!_running)
        {
            Log.Info("Listener thread waiting to come up");
            Thread.Sleep(500);
        }

        while (_running)
        {
            try
            {
                Log.Info($"Listening for TCP traffic on port {GetMyPort()}...");
                var actual = _comms.Receive(buffer, SocketFlags.None, out var code);
                Log.Warn($"Received {actual} bytes, code = {code.ToString()}");

                // TODO: unpack 'actual', and fix the headers and checksums.
                // Then send down the tunnel
                //_transport.Send(reply, Gateway);
            }
            catch (Exception ex)
            {
                Log.Error("Error in TCP listener", ex);
                Thread.Sleep(500);
            }
        }
        Log.Info("TCP listener ended");
    }

    /// <summary>
    /// Feed incoming message through the TCP state machine
    /// </summary>
    private bool HandleMessage(IpV4Packet ipv4, out TcpSegment tcp)
    {
        _stopwatch.Restart();
        
        // read the TCP segment
        var ok = ByteSerialiser.FromBytes(ipv4.Payload, out tcp);
        if (!ok)
        {
            Log.Warn("TCP payload did not parse");
            Log.Debug(Bit.Describe("ipv4 payload", ipv4.Payload));
            return false;
        }
        
        Log.Warn($"From {ipv4.Source.AsString}:{tcp.SourcePort} to {ipv4.Destination.AsString}:{tcp.DestinationPort}");

        // Re-target BOTH the ipv4 and tcp packets, and send them down our raw connection
        tcp.SourcePort = GetMyPort();
        ipv4.Destination = IpV4Address.LocalHost;
        ipv4.Source = IpV4Address.LocalHost;
        tcp.UpdateChecksum(ipv4);
        
        ipv4.Payload = ByteSerialiser.ToBytes(tcp);
        ipv4.UpdateChecksum();
        
        Log.Warn($"Routing as {ipv4.Source.AsString}:{tcp.SourcePort} to {ipv4.Destination.AsString}:{tcp.DestinationPort}");

        /*
2022-08-19T09:11 (utc) From 192.168.0.40:44378 to 55.55.55.55:5223
2022-08-19T09:11 (utc) Routing as 127.0.0.1:255 to 127.0.0.1:5223
2022-08-19T09:11 (utc) Send status = HostNotFound
2022-08-19T09:11 (utc) Sent 0 bytes from 60 byte message*/
        
        var raw = ByteSerialiser.ToBytes(ipv4);
        
        // IEB: un-bound mode --
        var actual = _comms.Send(raw, SocketFlags.None, out var errorCode);
        Log.Debug($"{actual} bytes sent. Send status = {errorCode.ToString()}");
        
        
        // IEB: bound mode--
        //var target = new IPEndPoint(IPAddress.Loopback, tcp.DestinationPort);
        //var actual = _comms.SendTo(raw, target);
        //var actual = _comms.SendTo(ipv4.Payload, target);
        //Log.Warn($"Sent {actual} bytes from {raw.Length} byte message");
        
        return true;
    }

    private int GetMyPort()
    {
        var endpoint = _comms.LocalEndPoint as IPEndPoint;
        if (endpoint is null)
        {
            Log.Info("Unbound");
            return 58255;
        }

        return endpoint.Port;
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
            PacketId = 123,//_rnd.Next(10, 32700),
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
        
        reply.UpdateChecksum();
        Log.Info($"IPv4 checksum={reply.Checksum:x4}");
        
        _transport.Send(reply, Gateway);
    }

    public void Close()
    {
        Log.Info($"Ending: {Bit.ToIpAddressString(RemoteAddress)}:{RemotePort} -> {Bit.ToIpAddressString(LocalAddress)}:{LocalPort}");
        _running = false;
        _comms.Close();
        _comms.Dispose();
        Log.Info($"TCP session ended: {Bit.ToIpAddressString(RemoteAddress)}:{RemotePort} -> {Bit.ToIpAddressString(LocalAddress)}:{LocalPort}");
    }
}