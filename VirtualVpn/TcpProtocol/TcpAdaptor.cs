using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Manages a single TCP session over a virtual connection through a ChildSA tunnel.
/// The actual TCP logic starts in <see cref="TcpSocket"/>
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
/// </summary>
public class TcpAdaptor : ITcpAdaptor
{
    /// <summary>
    /// The tunnel gateway we expect to be talking to
    /// </summary>
    public IPEndPoint Gateway { get; }

    /// <summary>
    /// The tunnel session we are connected to (used for sending replies)
    /// </summary>
    private readonly ChildSa _transport;

    private readonly SenderPort _selfKey;

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

    public TcpSocket TcpSocket { get; set; }

    public TcpAdaptor(ChildSa transport, IPEndPoint gateway, SenderPort selfKey)
    {
        _transport = transport;
        _selfKey = selfKey;
        
        Gateway = gateway;
        TcpSocket = new TcpSocket(this);
        LastContact = new Stopwatch();
    }

    /// <summary>
    /// Initiate a connection from a first incoming packet
    /// </summary>
    public bool Start(IpV4Packet ipv4)
    {
        Log.Debug("TCP session initiation");

        var ok = HandleMessage(ipv4, out var tcp);
        if (!ok)
        {
            Log.Debug("TCP session initiation failed");
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
    }

    /// <summary>
    /// Continue a session with a packet from the remote
    /// </summary>
    public void Accept(IpV4Packet ipv4)
    {
        LastContact.Restart(); // back to zero, keep counting
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

    public void Close()
    {
        Log.Info("Ending connection");
        // TODO: shut down this connection
        _transport.CloseConnection(_selfKey);
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
        
        // Pump through the TCP session logic
        TcpSocket.FeedIncomingPacket(tcp, ipv4);
        TcpSocket.EventPump();

        if (TcpSocket.State == TcpSocketState.Established
         && TcpSocket.ReadDataComplete)
        {
            var buffer = new byte[TcpSocket.BytesOfReadDataWaiting];
            var actual = TcpSocket.ReadData(buffer);
            var message = Encoding.UTF8.GetString(buffer, 0, actual);
            Log.Warn($"Complete message received, {actual} bytes of an expected {buffer.Length}. Message:\r\n{message}");
            
            // TODO: pass to the web app now, wait for response (maybe sending ACKs back to keep-alive?)
            //       then send the complete response back to tunnel
            
            // FAKE for now
            Log.Warn("Sending fake response");
            TcpSocket.SendData(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello"));
            while (TcpSocket.BytesOfSendDataWaiting > 0 && TcpSocket.ErrorCode == SocketError.Success)
            {
                TcpSocket.EventPump();
                Log.Warn($"{TcpSocket.BytesOfSendDataWaiting} bytes remaining");
                Thread.Sleep(250);
            }
        }

        return true;
    }

    /// <summary>
    /// Send a TCP packet back down the tunnel interface
    /// </summary>
    public void Reply(TcpSegment message, TcpRoute route)
    {
        // Set message checksum
        message.UpdateChecksum(route.LocalAddress.Value, route.RemoteAddress.Value);
        Log.Debug($"Tcp checksum={message.Checksum:x4} (" +
                  $"virtualSender={route.LocalAddress}, replyDest={route.RemoteAddress}, proto={(byte)IpV4Protocol.TCP}, " +
                  $"virtualPort={message.SourcePort}, replyPort={message.DestinationPort}, " +
                  $"seq={message.SequenceNumber}, ack#={message.AcknowledgmentNumber})");
        var tcpPayload = ByteSerialiser.ToBytes(message);
        
        // prepare container
        var reply = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + tcpPayload.Length,
            PacketId = 0, // TODO: fix this. Should be random
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.TCP,
            Checksum = 0,
            Source = route.LocalAddress,
            Destination = route.RemoteAddress,
            Options = Array.Empty<byte>(),
            Payload = tcpPayload
        };
        
        reply.UpdateChecksum();
        Log.Debug($"IPv4 checksum={reply.Checksum:x4}");
        
        Log.Info($"Sending message to tunnel {route.LocalAddress}:{message.SourcePort} -> {route.RemoteAddress}:{message.DestinationPort}");
        _transport.Send(reply, Gateway);
        TcpSocket.EventPump();
    }

    /// <summary>
    /// Trigger time-based actions.
    /// This should be called periodically
    /// <p></p>
    /// Returns true if any action was taken.
    /// </summary>
    public bool EventPump()
    {
        var acted = TcpSocket.EventPump();
        if (TcpSocket.ErrorCode != SocketError.Success) Log.Error($"Tcp virtual socket is in errored state: {TcpSocket.ErrorCode.ToString()}");
        return acted;
    }
}