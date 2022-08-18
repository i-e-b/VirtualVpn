
using System.Diagnostics;
using System.Net;
using RawSocketTest.Helpers;
using RawSocketTest.InternetProtocol;

namespace RawSocketTest.TransmissionControlProtocol;

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
    /// The tunnel gateway we expect to be talking to
    /// </summary>
    public IPEndPoint Gateway { get; }
    
    /// <summary>
    /// The tunnel session we are connected to (used for sending replies)
    /// </summary>
    private readonly ChildSa _transport;

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

    public TcpSession(ChildSa transport, IPEndPoint gateway)
    {
        _transport = transport;
        Gateway = gateway;
        
        State = TcpSocketState.Closed;
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

    private bool HandleMessage(IpV4Packet ipv4, out TcpSegment tcp)
    {
        var ok = ByteSerialiser.FromBytes(ipv4.Payload, out tcp);
        if (!ok)
        {
            Log.Warn("TCP payload did not parse");
            Log.Debug(Bit.Describe("ipv4 payload", ipv4.Payload));
            return false;
        }

        Log.Warn($"From {ipv4.Source.AsString}:{tcp.SourcePort} to {ipv4.Destination.AsString}:{tcp.DestinationPort}");
        Log.Warn($"Flags: {tcp.Flags.ToString()}, seq={tcp.SequenceNumber}, ack={tcp.AcknowledgmentNumber}");


        var reply = new IpV4Packet();
        _transport.Send(reply, Gateway);
        return true;
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
        // TODO: shut down this connection
    }
}