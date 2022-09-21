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
/// The actual TCP logic starts in <see cref="VirtualSocket"/>
/// https://en.wikipedia.org/wiki/Transmission_Control_Protocol
/// </summary>
public class TcpAdaptor : ITcpAdaptor
{
    /// <summary> The tunnel gateway we expect to be talking to </summary>
    public IPEndPoint Gateway { get; }

    /// <summary> The tunnel session we are connected to (used for sending replies) </summary>
    private readonly ChildSa _transport;

    /// <summary>
    /// The sender IP and Port number that uniquely identifies an active connection
    /// </summary>
    public SenderPort SelfKey { get; }

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
    private ISocketAdaptor? _realSocketToWebApp;

    /// <summary>
    /// Create a new adaptor to manage a TCP conversation.
    /// You can supply your own adaptor for the non-tunnelled part,
    /// or have a socket established
    /// </summary>
    /// <param name="transport">ChildSa that represents an open VPN tunnel</param>
    /// <param name="gateway">Remote gateway for the tunnel</param>
    /// <param name="selfKey">IP + port that is being used to key this conversation</param>
    /// <param name="socketAdaptor">Either an adaptor for the local data stream, or <c>null</c>.
    /// If null, a new TCP/IP socket will be opened.</param>
    public TcpAdaptor(ChildSa transport, IPEndPoint gateway, SenderPort selfKey, ISocketAdaptor? socketAdaptor)
    {
        _transport = transport;
        SelfKey = selfKey;
        _closeCalled = false;

        _realSocketToWebApp = socketAdaptor;

        Gateway = gateway;
        VirtualSocket = new TcpSocket(this);
        LastContact = new Stopwatch();
    }

    /// <summary>
    /// Initiate a connection with client on local side.
    /// Socket adaptor must be open and ready.
    /// </summary>
    public bool StartOutgoing(IpV4Address localAddress, int localPort, IpV4Address remoteAddress, int remotePort)
    {
        Log.Debug("TCP session initiation, from outgoing packet (we are client)");
        
        LastContact.Start(); // start counting. This gets reset every time we get another message

        // capture identity
        LocalAddress = localAddress.Value;
        LocalPort = localPort;
        RemoteAddress = remoteAddress.Value;
        RemotePort = remotePort;
        
        VirtualSocket.StartConnect(localAddress, (ushort)localPort, remoteAddress, (ushort)remotePort);

        Log.Debug("TCP session initiation started:" +
                  $" remote={Bit.ToIpAddressString(RemoteAddress)}:{RemotePort}," +
                  $" local={Bit.ToIpAddressString(LocalAddress)}:{LocalPort}");

        return true;
    }

    /// <summary>
    /// Initiate a connection from a first incoming packet from client on far side of tunnel.
    /// This will try to route to a local-side delegate.
    /// </summary>
    public bool StartIncoming(IpV4Packet ipv4)
    {
        Log.Debug("TCP session initiation, from incoming packet (we are server)");

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
        var ok = HandleMessage(ipv4, out _);
        if (ok)
        {
            Log.Trace("Restarting last contact timer");
            LastContact.Restart(); // back to zero, keep counting
        }
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
            _transport.TerminateConnection(SelfKey);
            Log.Info("Repeated call to TcpAdaptor.Close()");
            return;
        }

        _closeCalled = true;

        Log.Info("Ending connection");
        VirtualSocket.StartClose();
        _transport.TerminateConnection(SelfKey);
    }

    public void Closing()
    {
        Log.Trace("Started to close connection");
        _realSocketToWebApp?.Close();
        _transport.ReleaseConnection(SelfKey);
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
        VirtualSocket.FeedIncomingPacket(tcp, ipv4);
        VirtualSocket.EventPump(); // not strictly needed, but reduces latency a bit

        RunDataTransfer();
        return true;
    }

    #region Transfer between web app and VPN tunnel
    long _totalVirtualSent, _totalVirtualRead, _totalRealSent, _totalRealRead;
    bool _shutdownTransfer;
    private bool RunDataTransfer()
    {
        if (_shutdownTransfer) return false;

        Log.Trace($"### Run Data Transfer ### vRead={_totalVirtualRead}, rSend={_totalRealSent}, rRead={_totalRealRead}, vSend={_totalVirtualSent}," +
                  $" vSocket={VirtualSocket.State.ToString()}, webApp connected={_realSocketToWebApp?.Connected ?? false}");
        
        
        // If we are ready to talk to web app, make sure we have a real socket
        if (_realSocketToWebApp is null) Log.Trace("Connecting to web app");
        try
        {
            _realSocketToWebApp ??= ConnectToWebApp();
        }
        catch (Exception ex)
        {
            Log.Error("Can't connect to web app", ex);
            VirtualSocket.StartClose();
            _transport.TerminateConnection(SelfKey);
            return false;
        }

        if (_realSocketToWebApp is null)
        {
            Log.Trace($"Not ready to move data (no web app socket). Virtual socket has {VirtualSocket.BytesOfReadDataWaiting} bytes ready.");
            return false;
        }

        if (!_realSocketToWebApp.Connected)
        {
            Log.Trace("Web app socket is closed. Not transferring any data");
            return false;
        }

        Log.Trace($"Attempting tunnel<->webApp. Tunnel has {VirtualSocket.BytesOfReadDataWaiting} bytes ready. Web app has {_realSocketToWebApp?.Available ?? 0} bytes ready.");

        var anyData = false;

        // check to see if there is virtual port data to pass to the web app
        if (VirtualSocket.BytesOfReadDataWaiting > 0)
        {
            anyData |= MoveDataFromTunnelToWebApp();
        }
        else Log.Trace("Virtual socket is empty");

        // Read reply back from web app
        anyData |= MoveDataFromWebAppBackToTunnel();

        Log.Trace($"END Run Data Transfer anyMove={anyData}, vRead={_totalVirtualRead}, rSend={_totalRealSent}, rRead={_totalRealRead}, vSend={_totalVirtualSent}," +
                  $" vSocket={VirtualSocket.State.ToString()}, webApp connected={_realSocketToWebApp?.Connected ?? false}");

        if (_realSocketToWebApp?.Connected != true
            && _totalVirtualRead > 0
            && _totalVirtualSent > 0
            && VirtualSocket.BytesOfSendDataWaiting < 1)
        {
            // Everything is finished. Close down
            _shutdownTransfer = true;
            VirtualSocket.StartClose();
        }

        return anyData;
    }

    private bool MoveDataFromWebAppBackToTunnel()
    {
        try
        {
            var finalBytes = new List<byte>();

            if ((_realSocketToWebApp?.Available ?? 0) < 1)
            {
                Log.Trace("Web app reporting no data yet");
                return false;
            }

            if (VirtualSocket.State != TcpSocketState.Established)
            {
                Log.Trace("Virtual socket not ready yet");
                return false;
            }

            while (_realSocketToWebApp is not null
                   && _realSocketToWebApp.Available > 0)
            {
                Log.Debug("~~~~~~~~~~~~~~~~~~~~~Trying to receive~~~~~~~~~~~~~~~~~~~~");
                var received = _realSocketToWebApp.OutgoingFromLocal(_receiveBuffer);
                if (received > 0) finalBytes.AddRange(_receiveBuffer.Take(received));

                Log.Debug($"Got {received} bytes from socket");
            }

            Log.Debug($"Web app replied with {finalBytes.Count} bytes of data");

            var outgoingBuffer = finalBytes.ToArray();
            if (outgoingBuffer.Length > 0)
            {
                _totalRealRead += outgoingBuffer.Length;
                Log.Trace("OUTGOING:\r\n", () => Encoding.UTF8.GetString(outgoingBuffer));

                // Send reply back to virtual socket. The event pump will continue to send connection and state.
                VirtualSocket.SendData(outgoingBuffer);
                _totalVirtualSent += outgoingBuffer.Length;
                Log.Debug($"Virtual socket has {VirtualSocket.BytesOfSendDataWaiting} bytes remaining to send");
            }

            VirtualSocket.EventPump(); // not strictly needed, but reduces latency a bit
            return outgoingBuffer.Length > 0;
        }
        catch (Exception ex)
        {
            Log.Error("Failed to move data from Web App back to tunnel", ex);
            return false;
        }
    }
    
    private bool MoveDataFromTunnelToWebApp()
    {
        try
        {
            if (VirtualSocket.BytesOfReadDataWaiting < 1)
            {
                Log.Trace("No data to move to web app");
                return false;
            }

            // read from tunnel
            var buffer = new byte[VirtualSocket.BytesOfReadDataWaiting];
            var actual = VirtualSocket.ReadData(buffer);
            _totalVirtualRead += actual;
            Log.Info($"Message received from tunnel, {actual} bytes of an expected {buffer.Length}.");
            Log.Trace("INCOMING:\r\n", () => Encoding.UTF8.GetString(buffer, 0, actual));

            if (actual < 1) return false;
            
            // Send data to web app
            var sent = _realSocketToWebApp?.IncomingFromTunnel(buffer, 0, actual) ?? -1;
            if (sent != actual)
            {
                Log.Warn($"Unexpected send length. Tried to send {actual} bytes, but transmitted {sent} bytes.");
            }
            _totalRealSent += sent;

            Log.Trace($"Tunnel data sent to web app. {actual} bytes of {sent}.");

            return sent > 0;
        }
        catch (Exception ex)
        {
            Log.Error("Failed to move data from tunnel to Web App", ex);
            return false;
        }
    }

    private ISocketAdaptor ConnectToWebApp()
    {
        // Connect to web app
        Log.Debug("Connecting to web app");
        var webApiSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            webApiSocket.Connect(IpV4Address.FromString(Settings.WebAppIpAddress).MakeEndpoint(Settings.WebAppPort));
        }
        catch (SocketException ex)
        {
            switch (ex.SocketErrorCode)
            {
                case SocketError.AccessDenied:
                case SocketError.NetworkDown:
                case SocketError.NetworkUnreachable:
                case SocketError.ConnectionRefused:
                case SocketError.HostDown:
                case SocketError.HostUnreachable:
                    Log.Critical("Web App not available: can't respond to traffic.\r\nCheck web app is up and settings are correct");
                    throw;

                default:
                    throw;
            }
        }
        catch (Exception ex2)
        {
            if (ex2.Message.Contains("Connection refused"))
                Log.Critical("Web App not available: can't respond to traffic.\r\nCheck web app is up and settings are correct");
            throw;
        }

        Log.Debug("connection up");
        return new AdaptorForRealSocket(webApiSocket);
    }
    #endregion

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
        if (VirtualSocket.State == TcpSocketState.Closed)
        {
            Log.Trace("Virtual socket closed. Nothing to pump");
            return false;
        }

        var acted = RunDataTransfer();
        acted |= VirtualSocket.EventPump();
        Log.Trace($"Virtual socket state={VirtualSocket.State}");

        switch (VirtualSocket.ErrorCode)
        {
            case SocketError.Success:
            case SocketError.IsConnected:
                return acted;

            case SocketError.Disconnecting:
                Log.Info($"Tcp virtual socket is closing: code={VirtualSocket.ErrorCode.ToString()}, state={VirtualSocket.State.ToString()}");
                _transport.ReleaseConnection(SelfKey);
                return acted;

            case SocketError.NotConnected:
            case SocketError.Shutdown:
                Log.Info($"Tcp virtual socket is closed: code={VirtualSocket.ErrorCode.ToString()}, state={VirtualSocket.State.ToString()}");
                if (VirtualSocket.State == TcpSocketState.Closing)
                {
                    _transport.TerminateConnection(SelfKey);
                }
                else
                {
                    _transport.ReleaseConnection(SelfKey);
                }

                return acted;

            default:
                Log.Error($"Tcp virtual socket is in errored state: code={VirtualSocket.ErrorCode.ToString()}, state={VirtualSocket.State.ToString()}");
                _transport.ReleaseConnection(SelfKey);
                return false;
        }
    }
}