﻿using System.Diagnostics;
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
/// The actual TCP logic starts in <see cref="VirtualSocket"/>
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
/// </summary>
public class TcpAdaptor : ITcpAdaptor
{
    /// <summary> The tunnel gateway we expect to be talking to </summary>
    public IPEndPoint Gateway { get; }

    /// <summary> The tunnel session we are connected to (used for sending replies) </summary>
    private readonly ChildSa _transport;

    private readonly SenderPort _selfKey;
    
    // Transaction state triggers
    private volatile bool _closeCalled;
    
    private readonly byte[] _receiveBuffer = new byte[1800]; // big enough for a TCP packet

    /// <summary>
    /// Time since last packets send or received.
    /// Only starts ticking when first packets transmitted.
    /// </summary>
    public Stopwatch LastContact { get; set; }

    /// <summary> Address of remote side </summary>
    public byte[] RemoteAddress { get; private set; } = Array.Empty<byte>();

    /// <summary> Port declared by remote side </summary>
    public int RemotePort { get; private set; }

    /// <summary> Address requested for this session </summary>
    public byte[] LocalAddress { get; private set; } = Array.Empty<byte>();

    /// <summary> Local port requested for this session </summary>
    public int LocalPort { get; private set; }

    /// <summary> TcpSocket that represents the connection through the ChildSa tunnel </summary>
    public TcpSocket VirtualSocket { get; set; }

    /// <summary> Operating system socket connected to the web app </summary>
    private Socket? _realSocketToWebApp;
    
    public TcpAdaptor(ChildSa transport, IPEndPoint gateway, SenderPort selfKey)
    {
        _transport = transport;
        _selfKey = selfKey;
        _closeCalled = false;
        
        _realSocketToWebApp = null;
        
        Gateway = gateway;
        VirtualSocket = new TcpSocket(this);
        LastContact = new Stopwatch();
    }

    /// <summary>
    /// Initiate a connection from a first incoming packet
    /// </summary>
    public bool Start(IpV4Packet ipv4)
    {
        Log.Debug("TCP session initiation");
        
        VirtualSocket.Listen(); // must be in this state, or it will try to close the connection

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
        if (_closeCalled)
        {
            _realSocketToWebApp?.Dispose();
            _transport.TerminateConnection(_selfKey);
            Log.Trace("Repeated call to TcpAdaptor.Close()");
            return;
        }

        _closeCalled = true;
        
        Log.Info("Ending connection");
        VirtualSocket.StartClose();
        _transport.TerminateConnection(_selfKey);
    }

    public void Closing()
    {
        Log.Trace("Started to close connection");
        _realSocketToWebApp?.Close();
        _transport.ReleaseConnection(_selfKey);
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
        Log.Trace("### Data incoming...");
        VirtualSocket.FeedIncomingPacket(tcp, ipv4);
        VirtualSocket.EventPump(); // not strictly needed, but reduces latency a bit
        
        // Then check if we're ready to open a socket to the web app
        if (VirtualSocket.State != TcpSocketState.Established) return true; // not connected yet
        if (VirtualSocket.ReadDataState < TcpReadDataState.Cached) return true; // no data yet
        
        // We are ready to talk to web app. Make sure we have a real socket
        _realSocketToWebApp ??= ConnectToWebApp();

        // check to see if there is virtual port data to pass to the web app
        if (VirtualSocket.BytesOfReadDataWaiting > 0)
        {
            MoveDataFromTunnelToWebApp();
        }

        // Read reply back from web app
        MoveDataFromWebAppBackToTunnel();

        return true;
    }

    private void MoveDataFromWebAppBackToTunnel()
    {
        try
        {
            var finalBytes = new List<byte>();

            while (_realSocketToWebApp is not null
                   && _realSocketToWebApp.Available > 0)
            {
                Log.Debug("Trying to receive");
                var received = _realSocketToWebApp.Receive(_receiveBuffer);
                if (received > 0) finalBytes.AddRange(_receiveBuffer.Take(received));

                Log.Debug($"Got {received} bytes from socket");
            }

            Log.Info($"Web app replied with {finalBytes.Count} bytes of data");

            var outgoingBuffer = finalBytes.ToArray();
            Log.Trace("OUTGOING:\r\n", () => Encoding.UTF8.GetString(outgoingBuffer));

            // Send reply back to virtual socket. The event pump will continue to send connection and state.
            VirtualSocket.SendData(outgoingBuffer);
            Log.Debug($"Virtual socket has {VirtualSocket.BytesOfSendDataWaiting} bytes remaining to send");
            
            VirtualSocket.EventPump(); // not strictly needed, but reduces latency a bit
        }
        catch (Exception ex)
        {
            Log.Error("Failed to move data from Web App back to tunnel", ex);
        }
    }

    private void MoveDataFromTunnelToWebApp()
    {
        try
        {
            // read from tunnel
            var buffer = new byte[VirtualSocket.BytesOfReadDataWaiting];
            var actual = VirtualSocket.ReadData(buffer);
            Log.Info($"Complete message received, {actual} bytes of an expected {buffer.Length}.");
            Log.Trace("INCOMING:\r\n", () => Encoding.UTF8.GetString(buffer, 0, actual));

            // Send data to web app
            var sent = _realSocketToWebApp?.Send(buffer, 0, actual, SocketFlags.None) ?? -1;
            if (sent != actual)
            {
                Log.Warn($"Unexpected send length. Tried to send {actual} bytes, but transmitted {sent} bytes.");
            }
        }
        catch (Exception ex)
        {
            Log.Error("Failed to move data from tunnel to Web App", ex);
        }
    }

    private Socket ConnectToWebApp()
    {
        // Connect to web app
        Log.Debug("Connecting to web app");
        var webApiSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        webApiSocket.Connect(new IPAddress(Settings.WebAppIpAddress), Settings.WebAppPort);
        Log.Debug("connection up");
        return webApiSocket;
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
            PacketId = RandomPacketId(),
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
        VirtualSocket.EventPump();
    }

    /// <summary>
    /// Random for NON-crypto use
    /// </summary>
    private static readonly Random _rnd = new();
    private static int RandomPacketId() => _rnd.Next(1060, 64080);

    /// <summary>
    /// Trigger time-based actions.
    /// This should be called periodically
    /// <p></p>
    /// Returns true if any action was taken.
    /// </summary>
    public bool EventPump()
    {
        var acted = VirtualSocket.EventPump();

        switch (VirtualSocket.ErrorCode)
        {
            case SocketError.Success:
            case SocketError.IsConnected:
                return acted;
            
            case SocketError.Disconnecting:
                Log.Info($"Tcp virtual socket is closing: code={VirtualSocket.ErrorCode.ToString()}, state={VirtualSocket.State.ToString()}");
                _transport.ReleaseConnection(_selfKey);
                return acted;
            
            case SocketError.NotConnected:
            case SocketError.Shutdown:
                Log.Info($"Tcp virtual socket is closed: code={VirtualSocket.ErrorCode.ToString()}, state={VirtualSocket.State.ToString()}");
                if (VirtualSocket.State == TcpSocketState.Closing)
                {
                    _transport.TerminateConnection(_selfKey);
                }
                else
                {
                    _transport.ReleaseConnection(_selfKey);
                }

                return acted;
            
            default:
                Log.Error($"Tcp virtual socket is in errored state: code={VirtualSocket.ErrorCode.ToString()}, state={VirtualSocket.State.ToString()}");
                _transport.ReleaseConnection(_selfKey);
                return false;
        }
    }
}