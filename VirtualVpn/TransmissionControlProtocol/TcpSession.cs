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
    /// The low-level socket we use to send messages to our app.
    /// We listen on a different socket for reading.
    /// </summary>
    private readonly Socket _comms;
    
    /// <summary>
    /// The socket we use to capture traffic from our app.
    /// We send messages with a different port.
    /// </summary>
    private readonly Socket _appListenSocket;

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
    
    /// <summary>
    /// Start a new tunnelled TCP connection
    /// </summary>
    /// <param name="transport">VPN tunnel session</param>
    /// <param name="gateway">Gateway for VPN</param>
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
        Int16 protocol = 0x0800; // IP.
        _comms = new Socket(AddressFamily.Packet, SocketType.Raw, (ProtocolType)IPAddress.HostToNetworkOrder(protocol));

        _appListenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
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
        //var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        //interfaces[NetworkInterface.LoopbackInterfaceIndex]
        _comms.Bind(LowLevelEndPoint.GetFirstLoopback());
        _appListenSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        
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

        Log.Debug($"Listening for TCP traffic on {GetMyPort()}...");
        while (_running)
        {
            try
            {
                // This receives from *everything*
                var actual = _comms.Receive(buffer, SocketFlags.None, out var code);
                
                // so we filter aggressively
                if (actual < 14) continue; // junk packets
                if (code != SocketError.Success) continue;
                
                // fast check for IP Ether-type protocol (no deserialisation)
                if (buffer[12] != 0x08 || buffer[13] != 0x00 ) continue; // junk
                
                //Log.Debug(Bit.Describe("incoming packet", buffer, 0, actual));
                /*
                 var incoming_packet = new byte[] {
                 [ MAC                            ]   [ MAC                            ]
                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  0x00, 0x20, 0x01, 0x02, 0x03, 0x04,
                 
                 [ IP Ether-type]
                 0x08, 0x00,
                 
                 [ IPv4 packet...
                 0x45, 0x00, 0x00, 0x3C, 0x2F, 0xC9, 0x40, 0x00, 0x40, 0x06, 0x0C, 0xF1, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xAE, 0xAB, 0x14, 0x67, 0x05, 0x25, 0x37, 0x70, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x02, 0xFD, 0x2D, 0x1E, 0xD4, 0x00, 0x00, 0x02, 0x04, 0x05, 0x63, 0x04, 0x02, 0x08, 0x0A, 0x85, 0xE7, 0xA8, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07, 0x00, 0x00, 0x00, 0xF8, 0x35, 0xF8, 0xD7, };
*/
                
                // ok, it *might* be for us. Read the header properly
                _ = ByteSerialiser.FromBytes<IpV4Packet>(buffer, 14, 20 /*only the headers*/, out var packet);
                //if (!packet.Destination.IsLocalHost) continue; // junk
                
                Log.Debug($"Captured {packet.Protocol.ToString()}: {packet.Source.AsString} -> {packet.Destination.AsString}; code={code.ToString()}");

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
        
        var raw = ByteSerialiser.ToBytes(ipv4);
        
        // IEB: this might need an ethernet frame on it?
        // https://github.com/dotpcap/packetnet
        // https://en.wikipedia.org/wiki/Ethernet_frame

        /*
11:06:34.009558 IP localhost.49615 > localhost.domain: 46740+ [1au] PTR? 53.0.0.127.in-addr.arpa. (52)
11:06:34.009861 IP localhost.domain > localhost.49615: 46740*$ 1/0/1 PTR localhost. (75)
11:06:47.684389 07:08:09:10:11:12 (oui Unknown) > 01:02:03:04:05:06 (oui Unknown), ethertype Unknown (0x1314), length 24:
        0x0000:  1516 1718 1920 2122 2324                 ......!"#$
11:06:48.611624 07:08:09:10:11:12 (oui Unknown) > 01:02:03:04:05:06 (oui Unknown), ethertype Unknown (0x1314), length 24:
        0x0000:  1516 1718 1920 2122 2324                 ......!"#$
*/
        // IPv4 is type 0x0800
        //                             [ --- destination MAC ---------- ]  [ --- source MAC --------------- ]  [ type   ]  [ --- data ...
        var testPattern = new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x20, 0x01, 0x02, 0x03, 0x04, 0x08, 0x00 };
        // then a CRC at the end
        // Broadcast address is 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ???
        
        var encapsulated = testPattern.Concat(raw).Concat(new byte[7]).ToArray();
        var crc = Crc32.Compute(encapsulated);
        
        encapsulated[^1] = (byte)((crc >>  0) & 0xff);
        encapsulated[^2] = (byte)((crc >>  8) & 0xff);
        encapsulated[^3] = (byte)((crc >> 16) & 0xff);
        encapsulated[^4] = (byte)((crc >> 24) & 0xff);
        
        var actual = _comms.Send(encapsulated, SocketFlags.None, out var errorCode);
        Log.Debug($"{actual} bytes sent. Send status = {errorCode.ToString()}");
        
        return true;
    }

    private int GetMyPort()
    {
        return (_appListenSocket.LocalEndPoint as IPEndPoint)?.Port ?? 58111;
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