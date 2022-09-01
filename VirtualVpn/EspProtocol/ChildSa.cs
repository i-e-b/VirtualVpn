using System.Net;
using VirtualVpn.Crypto;
using VirtualVpn.Enums;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;
using VirtualVpn.TcpProtocol;

// ReSharper disable BuiltInTypeReferenceStyle

namespace VirtualVpn.EspProtocol;

public class ChildSa : ITransportTunnel
{
    public UInt32 SpiIn { get; }
    public UInt32 SpiOut { get; }
    public IpV4Address Gateway { get; set; }

    // pvpn/server.py:18
    public ChildSa(IpV4Address gateway, byte[] spiIn, byte[] spiOut, IkeCrypto cryptoIn, IkeCrypto cryptoOut, IUdpServer? server)
    {
        Gateway = gateway;
        _spiIn = spiIn;
        _spiOut = spiOut;
        _cryptoIn = cryptoIn;
        _cryptoOut = cryptoOut;
        _server = server;

        _msgIdIn = 1;
        _msgIdOut = 1;
        
        var idx = 0;
        SpiIn = Bit.ReadUInt32(spiIn, ref idx);
        idx = 0;
        SpiOut = Bit.ReadUInt32(spiOut, ref idx);
    }

    public void IncrementMessageId(uint espPacketSequence)
    {
        _msgIdIn = (int)(espPacketSequence+1);
    }

    /// <summary>
    /// Drive timed events. This method should be called periodically, usually by <see cref="VpnServer.EventPumpLoop"/>
    /// <p></p>
    /// Returns true if any action was taken.
    /// </summary>
    public bool EventPump()
    {
        // TODO: if we are the initiator, we should send periodic keep-alive pings to the peer.
        
        
        // Check TCP sessions, close them if they are timed out.
        var acted = false;
        var allSessions = _tcpSessions.Keys.ToList();
        foreach (var tcpKey in allSessions)
        {
            var tcp = _tcpSessions[tcpKey];
            if (tcp is null) continue;
            
            if (tcp.LastContact.Elapsed > Settings.TcpTimeout)
            {
                Log.Debug($"Old session: {tcp.LastContact.Elapsed}; remote={Bit.ToIpAddressString(tcp.RemoteAddress)}:{tcp.RemotePort}," +
                          $" local={Bit.ToIpAddressString(tcp.LocalAddress)}:{tcp.LocalPort}. Closing");
                TerminateConnection(tcpKey);
            }
            else if (tcp.VirtualSocket.State == TcpSocketState.Closed)
            {
                Log.Debug($"Old session closed: {Bit.ToIpAddressString(tcp.RemoteAddress)}:{tcp.RemotePort} -> {Bit.ToIpAddressString(tcp.LocalAddress)}:{tcp.LocalPort}");
                TerminateConnection(tcpKey);
            }
            else
            {
                acted |= tcp.EventPump();
            }
        }

        // Old sessions that are shutting down.
        // They are no longer keyed.
        foreach (var oldKey in _parkedSessions.Keys)
        {
            var oldSession = _parkedSessions[oldKey];
            if (oldSession is null) continue;
            
            if (oldSession.VirtualSocket.State == TcpSocketState.Closed) _parkedSessions.Remove(oldKey);
            else oldSession.EventPump();
        }
        return acted;
    }
    
    /// <summary>
    /// Release the sender/port binding for the connection,
    /// but keep pumping events until it completes shutdown.
    /// </summary>
    public void ReleaseConnection(SenderPort key)
    {
        var session = _tcpSessions.Remove(key);
        if (session is not null)
        {
            _parkedSessions[key] = session;
        }
    }

    /// <summary>
    /// Write SPE packet for an IPv4 payload.
    /// Encrypts and adds SPE checksum. IPv4 checksum must be written before calling
    /// </summary>
    public byte[] WriteSpe(IpV4Packet packet)
    {
        var plain = ByteSerialiser.ToBytes(packet);
        var encrypted = _cryptoOut.EncryptEsp(plain, IpProtocol.IPV4);

        CaptureTraffic(plain, "out");

        var wrapper = new EspPacket{
            Sequence = (uint)_msgIdOut,
            Spi = SpiOut,
            Payload = encrypted
        };
        
        var message = ByteSerialiser.ToBytes(wrapper);
        _cryptoOut.AddChecksum(message, Array.Empty<byte>());
        return message;
    }

    public IpV4Packet ReadSpe(byte[] encrypted, out EspPacket espPacket)
    {
        // sanity check
        if (encrypted.Length < 8) throw new Exception("EspPacket too short");
        
        var ok = ByteSerialiser.FromBytes(encrypted, out espPacket);
        if (!ok) throw new Exception("Failed to deserialise EspPacket");

        // target check
        if (espPacket.Spi != SpiIn) throw new Exception($"Mismatch SPI. Expected {SpiIn:x8}, got {espPacket.Spi:x8}");
        if (espPacket.Sequence < _msgIdIn) throw new Exception($"Mismatch Sequence. Expected {_msgIdIn}, got {espPacket.Sequence}");
        
        // checksum
        var checkOk = _cryptoIn.VerifyChecksum(encrypted);
        if (!checkOk) throw new Exception("ESP Checksum failed");

        // decode
        var plain = _cryptoIn.DecryptEsp(espPacket.Payload, out var declaredProtocol);
        
        if (declaredProtocol != IpProtocol.IPV4) throw new Exception($"ESP delivered unsupported payload type: {declaredProtocol.ToString()}");
        
        CaptureTraffic(plain, "in");
        
        ok = ByteSerialiser.FromBytes<IpV4Packet>(plain, out var ipv4);
        if (!ok) throw new Exception("Failed to deserialise IPv4 packet");
        
        return ipv4;
    }
    
    /// <summary>
    /// Send a message through the gateway.
    /// Used by protocol layer (e.g. TCP).
    /// IPv4 checksum must be written before calling
    /// </summary>
    public void Send(IpV4Packet reply, IPEndPoint gateway)
    {
        Log.Info("Sending reply");
        var raw = WriteSpe(reply);
        Reply(raw, gateway);
    }
    
    
    private readonly byte[] _spiIn;
    private readonly byte[] _spiOut;
    private readonly IkeCrypto _cryptoIn;
    private readonly IkeCrypto _cryptoOut;
    private readonly IUdpServer? _server;
    private long _msgIdIn;
    private long _msgIdOut;
    private long _captureNumber;
    
    private readonly ThreadSafeMap<SenderPort, TcpAdaptor> _tcpSessions = new();
    private readonly ThreadSafeMap<SenderPort, TcpAdaptor> _parkedSessions = new();
    
    /// <summary>
    /// Immediately remove the connection from sessions and stop event pump
    /// </summary>
    internal void TerminateConnection(SenderPort key)
    {
        try
        {
            var session = _tcpSessions.Remove(key);
            session?.Close();
            
            _parkedSessions.Remove(key);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to close TCP session: {ex}");
        }
    }

    public void HandleSpe(byte[] data, IPEndPoint sender)
    {
        Log.Info($"HandleSpe: data={data.Length} bytes, sender={sender}");
        
        var incomingIpv4Message = ReadSpe(data, out var espPkt);


        switch (incomingIpv4Message.Protocol)
        {
            case IpV4Protocol.ICMP:
            {
                Log.Info("ICMP payload found");
                HandleIcmp(sender, incomingIpv4Message);
                break;
            }
            case IpV4Protocol.TCP:
            {
                Log.Info("Regular TCP/IP packet");
                HandleTcp(sender, incomingIpv4Message);
                break;
            }
            case IpV4Protocol.UDP:
            {
                Log.Info("UDP packet tunnelled in. Not responding.");
                break;
            }
            case IpV4Protocol.AH:
            case IpV4Protocol.ESP:
            case IpV4Protocol.GRE:
            case IpV4Protocol.VRRP:
            case IpV4Protocol.L2TP:
            case IpV4Protocol.MPLS_in_IP:
            case IpV4Protocol.WESP:
                Log.Error($"Another VPN-like protocol ({incomingIpv4Message.Protocol.ToString()}) was tunnelled through this VPN link. This is likely a misconfiguration.");
                break;
            
            default:
                Log.Warn($"Unsupported protocol delivered ({incomingIpv4Message.Protocol.ToString()})");
                break;
        }
        
        

        IncrementMessageId(espPkt.Sequence);
        
        // dump the crypto details if requested
        if (Settings.CaptureTraffic)
        {
            File.WriteAllText(Settings.FileBase + "CSA.txt",
                Bit.Describe("SPI-in", _spiIn) +
                Bit.Describe("SPI-out", _spiOut) +
                "\r\nCryptoIn=" + _cryptoIn.UnsafeDump() +
                "\r\nCryptoOut=" + _cryptoOut.UnsafeDump()
            );
        }
    }

    private void HandleTcp(IPEndPoint sender, IpV4Packet incomingIpv4Message)
    {
        try
        {
            var key = TcpAdaptor.ReadSenderAndPort(incomingIpv4Message);
            if (key.DestinationPort == 0 || key.SenderAddress == 0)
            {
                Log.Info("Invalid TCP/IP request: address or port not recognised");
                return;
            }

            // Is it a known session?
            var session = _tcpSessions[key];
            if (session is not null)
            {
                // check that this session is still coming through the original tunnel
                if (!session.Gateway.Address.Equals(sender.Address))
                {
                    Log.Warn($"Crossed connection in TCP? Expected gateway {session.Gateway.Address}, but got gateway {sender.Address} -- not replying");
                    return;
                }

                // continue existing session
                session.Accept(incomingIpv4Message);
            }
            else
            {
                // start new session
                var newSession = new TcpAdaptor(this, sender, key);
                var sessionOk = newSession.Start(incomingIpv4Message);
                if (sessionOk) _tcpSessions[key] = newSession;
            }
        }
        catch (Exception ex)
        {
            Log.Error("Error in TCP path", ex);
        }
    }

    private void HandleIcmp(IPEndPoint sender, IpV4Packet incomingIpv4Message)
    {
        try
        {
            var ok = ByteSerialiser.FromBytes<IcmpPacket>(incomingIpv4Message.Payload, out var icmp);
            if (!ok) throw new Exception("Could not read ICMP packet");

            if (icmp.MessageType == IcmpType.EchoRequest) // this is a ping!
            {
                ReplyToPing(sender, icmp, incomingIpv4Message);
            }
            else Log.Debug($"Unsupported ICMP message '{icmp.MessageType.ToString()}' -- not replying");
        }
        catch (Exception ex)
        {
            Log.Error("Error in ICMP path", ex);
        }
    }

    private void ReplyToPing(IPEndPoint sender, IcmpPacket icmp, IpV4Packet incomingIpv4Message)
    {
        Log.Info("    It's a ping. Constructing reply.");
        icmp.MessageType = IcmpType.EchoReply;
        icmp.MessageCode = 0;
        icmp.Checksum = 0;

        var checksum = IpChecksum.CalculateChecksum(ByteSerialiser.ToBytes(icmp));
        icmp.Checksum = checksum;

        var icmpData = ByteSerialiser.ToBytes(icmp);
        var ipv4Reply = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + icmpData.Length, // calculate later?
            PacketId = 642, // should be random?
            Flags = IpV4HeaderFlags.DontFragment,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.ICMP,
            Checksum = 0,
            Source = incomingIpv4Message.Destination,
            Destination = incomingIpv4Message.Source,
            Options = Array.Empty<byte>(),
            Payload = icmpData
        };
        
        ipv4Reply.UpdateChecksum();

        var encryptedData = WriteSpe(ipv4Reply);
        Reply(encryptedData, sender);
    }
    
    private void Reply(byte[] message, IPEndPoint to)
    {
        if (_server is null)
        {
            Log.Warn($"Can't send to {to.Address}, this Child SA has no UDP server connection");
            return;
        }
        
        _server.SendRaw(message, to);

        _msgIdOut++;
    }

    private void CaptureTraffic(byte[] plain, string direction)
    {
        if (!Settings.CaptureTraffic) return;
        
        File.WriteAllText(Settings.FileBase + $"IPv4_{_captureNumber}_{direction}.txt", Bit.Describe($"ipv4_{_captureNumber}_{direction}", plain));
        _captureNumber++;
    }
}