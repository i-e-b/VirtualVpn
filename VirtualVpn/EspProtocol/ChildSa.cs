using System.Diagnostics;
using System.Net;
using VirtualVpn.Crypto;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol.Payloads;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;
using VirtualVpn.TcpProtocol;

// ReSharper disable BuiltInTypeReferenceStyle

namespace VirtualVpn.EspProtocol;

/// <summary>
/// This manages the Security Associations that tunnel traffic
/// between gateways. Called "Child SA" because they are made
/// by a "Parent" IKE session.
/// </summary>
public class ChildSa : ITransportTunnel
{
    // Static port rotator
    private static ushort _portIncrement;
    
    // Keys
    public UInt32 SpiIn { get; }
    public UInt32 SpiOut { get; }
    public IpV4Address Gateway { get; set; }
    public VpnSession? Parent { get; }
    
    // Stats
    public ulong DataIn { get; set; }
    public ulong DataOut { get; set; }
    public ulong MessagesIn { get; set; }
    public ulong MessagesOut { get; set; }
    
    
    private readonly byte[] _spiIn;
    private readonly byte[] _spiOut;
    private readonly IkeCrypto _cryptoIn;
    private readonly IkeCrypto _cryptoOut;
    private readonly IUdpServer? _server;
    private readonly PayloadTsx? _trafficSelect;
    private long _msgIdIn;
    private long _msgIdOut;
    private long _captureNumber;
    
    private readonly ThreadSafeMap<SenderPort, ITcpAdaptor> _tcpSessions = new();
    private readonly ThreadSafeMap<SenderPort, ITcpAdaptor> _parkedSessions = new();
    private readonly EspTimedEvent _keepAliveTrigger;
    private readonly Stopwatch _pingTimer; // for pings we send

    private static readonly Random _rnd = new();
    private static int RandomPacketId() => _rnd.Next();
    

    // pvpn/server.py:18
    public ChildSa(IpV4Address gateway, byte[] spiIn, byte[] spiOut, IkeCrypto cryptoIn, IkeCrypto cryptoOut,
        IUdpServer? server, VpnSession? parent, PayloadTsx? trafficSelect)
    {
        Gateway = gateway;
        _spiIn = spiIn;
        _spiOut = spiOut;
        _cryptoIn = cryptoIn;
        _cryptoOut = cryptoOut;
        _server = server;
        Parent = parent;
        _trafficSelect = trafficSelect;
        _pingTimer = new Stopwatch();

        _keepAliveTrigger = new EspTimedEvent(KeepAliveEvent, Settings.KeepAliveTimeout);

        _msgIdIn = 1;
        _msgIdOut = 1;
        
        var idx = 0;
        SpiIn = Bit.ReadUInt32(spiIn, ref idx);
        idx = 0;
        SpiOut = Bit.ReadUInt32(spiOut, ref idx);
    }

    /// <summary>
    /// Provide a description of each known TCP session
    /// in this ChildSa
    /// </summary>
    public List<string> ListTcpSessions()
    {
        var result = new List<string>();

        foreach (var session in _tcpSessions.Keys)
        {
            var tcp = _tcpSessions[session];
            if (tcp is null)
            {
                result.Add($"INVALID SESSION: {session.Address}:{session.Port}");
            }
            else
            {
                result.Add($"ACTIVE: {session.Address.AsString}:{session.Port} - {tcp.SocketThroughTunnel.State.ToString()} ( {IpV4Address.Describe(tcp.LocalAddress)}:{tcp.LocalPort}->{IpV4Address.Describe(tcp.RemoteAddress)}:{tcp.RemotePort} )");
            }
        }
        
        foreach (var session in _parkedSessions.Keys)
        {
            var tcp = _parkedSessions[session];
            if (tcp is null)
            {
                result.Add($"INVALID PARKED SESSION: {session.Address}:{session.Port}");
            }
            else
            {
                result.Add($"PARKED: {session.Address}:{session.Port} - {tcp.SocketThroughTunnel.State.ToString()} ( {IpV4Address.Describe(tcp.LocalAddress)}:{tcp.LocalPort}->{IpV4Address.Describe(tcp.RemoteAddress)}:{tcp.RemotePort} )");
            }
        }
        
        return result;
    }

    private void KeepAliveEvent(EspTimedEvent obj)
    {
        Log.Debug($"Sending keep-alive to {Gateway.AsString}:{4500}");
        _keepAliveTrigger.Reset();
        _server?.SendRaw(new byte[]{ 0xff }, Gateway.MakeEndpoint(4500));
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
        var goFaster = false;
        
        // if we are the initiator, we should send periodic keep-alive pings to the peer.
        if (Parent?.WeStarted == true)
        {
            _keepAliveTrigger.TriggerIfExpired();
        }

        // Check TCP sessions, close them if they are timed out.
        var allSessions = _tcpSessions.Keys.ToList();
        foreach (var tcpKey in allSessions)
        {
            goFaster = true; // go fast if there are any open connections
            if (tcpKey.Address.IsZero())
            {
                Log.Critical("Stored a tcp session with a zero value key!");
                _tcpSessions.Remove(tcpKey);
                continue;
            }

            var tcp = _tcpSessions[tcpKey];
            if (tcp is null)
            {
                Log.Debug("Null session found. Removing");
                _tcpSessions.Remove(tcpKey);
                continue;
            }

            if (tcp.LastContact.Elapsed > Settings.TcpTimeout)
            {
                Log.Debug($"Old session: {tcp.LastContact.Elapsed}; remote={Bit.ToIpAddressString(tcp.RemoteAddress)}:{tcp.RemotePort}," +
                          $" local={Bit.ToIpAddressString(tcp.LocalAddress)}:{tcp.LocalPort}. Closing");
                TerminateConnection(tcpKey);
            }
            else if (tcp.TunnelConnectionIsClosedOrFaulted())
            {
                Log.Debug($"Old session closed: {Bit.ToIpAddressString(tcp.RemoteAddress)}:{tcp.RemotePort} -> {Bit.ToIpAddressString(tcp.LocalAddress)}:{tcp.LocalPort}");
                TerminateConnection(tcpKey);
            }
            else if (tcp.WebAppConnectionIsFaulted())
            {
                Log.Debug($"Connection to web app faulted, disconnecting: {Bit.ToIpAddressString(tcp.RemoteAddress)}:{tcp.RemotePort} -> {Bit.ToIpAddressString(tcp.LocalAddress)}:{tcp.LocalPort}");
                TerminateConnection(tcpKey);
            }

            try
            {
                tcp.EventPump();
            }
            catch (Exception ex)
            {
                Log.Error("Unhandled exception in ChildSa EventPump (active session)", ex);
            }
        }

        // Old sessions that are shutting down.
        // They are no longer keyed.
        var parkedKeys = _parkedSessions.Keys.ToArray();
        foreach (var oldKey in parkedKeys)
        {
            var oldSession = _parkedSessions[oldKey];
            if (oldSession is null)
            {
                _parkedSessions.Remove(oldKey);
                continue;
            }
            
            if (oldSession.LastContact.Elapsed > Settings.TcpTimeout)
            {
                Log.Debug($"Old session: {oldSession.LastContact.Elapsed}; remote={Bit.ToIpAddressString(oldSession.RemoteAddress)}:{oldSession.RemotePort}," +
                          $" local={Bit.ToIpAddressString(oldSession.LocalAddress)}:{oldSession.LocalPort}. Closing");
                _parkedSessions.Remove(oldKey);
            }

            if (oldSession.SocketThroughTunnel.State is TcpSocketState.Closed or TcpSocketState.Listen)
            {
                _parkedSessions.Remove(oldKey);
            }
            else
            {
                try
                {
                    oldSession.EventPump();
                }
                catch (Exception ex)
                {
                    Log.Error("Unhandled exception in ChildSa EventPump (old session)", ex);
                }
            }
        }
        return goFaster;
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

    /// <summary>
    /// Public for testing reasons. This should only be called by <see cref="HandleSpe"/>
    /// </summary>
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
        if (!checkOk)
        {
            if (_cryptoOut.VerifyChecksum(encrypted)) { Log.Critical("Crypto settings are reversed. This is likely a code fault."); }

            throw new Exception("ESP Checksum failed");
        }

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
        Log.Trace("ChildSa - Sending packet through gateway");
        var raw = WriteSpe(reply);
        UdpDataSend(raw, gateway);
    }
    
    /// <summary>
    /// Immediately remove the connection from sessions and stop event pump
    /// </summary>
    internal void TerminateConnection(SenderPort key)
    {
        try
        {
            if (key.Address.IsZero() || key.Port == 0)
            {
                Log.Critical($"ChildSa.TerminateConnection was passed an invalid key: {key.Describe()}; " +
                             $"Known keys are: {string.Join(", ", _tcpSessions.Keys.Select(x => x.Describe()))}");
            }
            if (key.Port < 1024) { Log.Critical("Non-ephemeral port was used as a session key. This will break the routing logic!"); }
            
            Log.Debug($"Trying to remove {key.Describe()}");
            
            var session = _tcpSessions.Remove(key);
            if (session is not null)
            {
                Log.Info($"Parking {session.Describe()}");
            }


            session = _parkedSessions.Remove(key);
            if (session is not null)
            {
                Log.Info($"Terminating {session.Describe()}");
            }
            
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to close TCP session: {ex}");
        }
    }

    public void HandleSpe(byte[] data, IPEndPoint sender)
    {
        Log.Trace($"HandleSpe: data={data.Length} bytes, sender={sender}");
        
        Parent?.UpdateTrafficTimeout();
        var incomingIpv4Message = ReadSpe(data, out var espPkt);
        MessagesIn++;
        DataIn += (ulong)data.Length;

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
                Log.Trace("Regular TCP/IP packet");
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
            if (key.Port == 0 || key.Address.IsZero())
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
                    Log.Critical($"Crossed connection in TCP? Expected gateway {session.Gateway.Address}, but got gateway {sender.Address} -- not replying");
                    return;
                }

                if (session.WebAppConnectionIsFaulted()
                    || session.TunnelConnectionIsClosedOrFaulted()
                    )
                {
                    Log.Critical("Data still incoming to broken connection!");
                    Log.Info("Removing session, will try to make it fall through to a new one");
                    _tcpSessions.Remove(key);
                }
                else
                {
                    Log.Trace($"#################### ACTIVE Virtual Socket-- state={session.SocketThroughTunnel.State}; error code={session.SocketThroughTunnel.ErrorCode}");

                    // continue existing session
                    session.Accept(incomingIpv4Message);
                    return;
                }
            }
            
            // check this is valid as the start of a new session
            var ok = ByteSerialiser.FromBytes<TcpSegment>(incomingIpv4Message.Payload, out var tcp);
            if (!ok)
            {
                Log.Info($"Rejecting invalid TCP/IP request: {incomingIpv4Message.Destination.AsString}:{tcp.DestinationPort} ({tcp.Flags.ToString()})");
                return;
            }

            var parked = _parkedSessions[key];
            if (parked is not null && tcp.Flags.FlagsClear(TcpSegmentFlags.Syn))
            {
                if (parked.WebAppConnectionIsFaulted() || parked.TunnelConnectionIsClosedOrFaulted())
                {
                    Log.Trace($"####################  PARKED Virtual Socket-- state={parked.SocketThroughTunnel.State}; error code={parked.SocketThroughTunnel.ErrorCode}");
                    Log.Info("Parked session in closed or faulted state. Will remove, and start a new session.");
                    _parkedSessions.Remove(key);
                    // don't return.
                }
                else
                {
                    // kick a parked session? This should be FIN etc.
                    Log.Trace($"####################  PARKED Virtual Socket-- tcp flags={tcp.Flags.ToString()}; state={parked.SocketThroughTunnel.State}; error code={parked.SocketThroughTunnel.ErrorCode}");
                    parked.Accept(incomingIpv4Message);
                    return;
                }
            }

            // Not a known session

            // Check for shut-down messages
            if (tcp.Flags.FlagsSet(TcpSegmentFlags.FinAck))
            {
                Log.Debug($"Got FIN/ACK from {incomingIpv4Message.Source.AsString}. Sending final ACK");
                ReplyToFinAck(incomingIpv4Message, tcp, sender);
                return;
            }
                
            if (tcp.Flags.FlagsSet(TcpSegmentFlags.Ack) || tcp.Flags.FlagsSet(TcpSegmentFlags.Rst))
            {
                Log.Debug("Got end-of-stream message for a stream we already closed. Ignoring");
                return;
            }

            if (!tcp.Flags.FlagsSet(TcpSegmentFlags.Syn))
            {
                // Looks ok, but it's not the start of a TCP stream.
                // This might happen if we get FIN messages for sessions we've already abandoned
                Log.Warn($"Rejecting TCP/IP request due to invalid flags: {incomingIpv4Message.Destination.AsString}:{tcp.DestinationPort} ({tcp.Flags.ToString()})");
                return;
            }

            // Final check
            if (key.Port == 0 || key.Address.IsZero())
            {
                Log.Critical("Lost valid TCP/IP request: address or port went zero");
                return;
            }
            
            // start new session
            var newSession = new TcpAdaptor(this, sender, key, null);
            var sessionOk = newSession.StartIncoming(incomingIpv4Message);
            if (sessionOk)
            {
                _tcpSessions[key] = newSession;
                Log.Info($"Session started {key.Describe()}");
            }
            else
            {
                Log.Warn($"Could not start session {key.Describe()}");
            }
        }
        catch (Exception ex)
        {
            Log.Error("Error in TCP path", ex);
        }
    }

    /// <summary>
    /// Send a final close message back, without caring about the actual TCP session
    /// </summary>
    private void ReplyToFinAck(IpV4Packet ipv4, TcpSegment tcp, IPEndPoint sender)
    {
        var replyTcp = new TcpSegment
        {
            SourcePort = tcp.DestinationPort,
            DestinationPort = tcp.SourcePort,
            SequenceNumber = tcp.SequenceNumber,
            AcknowledgmentNumber = tcp.AcknowledgmentNumber,
            DataOffset = 5,
            Reserved = 0,
            Flags = TcpSegmentFlags.Ack,
            WindowSize = 0,
            Checksum = 0,
            UrgentPointer = 0
        };
        var replyIpv4 = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            PacketId = 101,
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.TCP,
            Checksum = 0,
            Source = ipv4.Destination,
            Destination = ipv4.Source,
        };
        
        replyTcp.UpdateChecksum(replyIpv4.Source.Value, replyIpv4.Destination.Value);
        replyIpv4.Payload = ByteSerialiser.ToBytes(replyTcp);
        replyIpv4.TotalLength = 20 + replyIpv4.Payload.Length;
        
        replyIpv4.UpdateChecksum();
        
        var encryptedData = WriteSpe(replyIpv4);
        UdpDataSend(encryptedData, sender);
    }
    
    /// <summary>
    /// Open a new TCP session with local side as the client,
    /// and far side of tunnel as server.
    /// </summary>
    public ITcpAdaptor OpenTcpSession(IpV4Address targetAddress, int targetPort, IpV4Address proxyLocalAddress, ISocketAdaptor apiSide)
    {
        if (targetAddress.IsZero()) throw new Exception("Invalid target address given to OpenTcpSession");
        if (Gateway.IsZero()) throw new Exception("Invalid gateway in OpenTcpSession");
        
        var key = GetAvailableKey(targetAddress);
        var newSession = new TcpAdaptor(this, Gateway.MakeEndpoint(4500), key, apiSide);
        var sessionOk = newSession.StartOutgoing(proxyLocalAddress, key.Port, targetAddress, targetPort);
        if (sessionOk) _tcpSessions[key] = newSession;
        return newSession;
    }

    /// <summary>
    /// Find an ephemeral port that is not in use
    /// </summary>
    private SenderPort GetAvailableKey(IpV4Address target)
    {
        if (target.IsZero())
        {
            Log.Critical("Created invalid SenderPort!");
            throw new Exception("Created invalid SenderPort");
        }

        // rotate ports, because if we re-use them too soon the other VPN can get confused
        var port = 1060 + (_portIncrement & 0x7FFF);
        _portIncrement++;
        
        var key = new SenderPort(target.Value, port);
        while (_tcpSessions.ContainsKey(key) || _parkedSessions.ContainsKey(key))
        {
            port++;
            if (port > 65535) throw new Exception("Ephemeral ports exhausted");
            key = new SenderPort(target.Value, port);
        }

        return key;
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
            else if (icmp.MessageType == IcmpType.EchoReply)
            {
                _pingTimer.Stop();
                Log.Info($"    ICMP ping reply\r\n Time={_pingTimer.ElapsedMilliseconds}ms, Responder={incomingIpv4Message.Source}, Gateway={sender.Address}:{sender.Port}.");
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
            TotalLength = 20 + icmpData.Length,
            PacketId = RandomPacketId(),
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
        UdpDataSend(encryptedData, sender);
    }
    
    private void UdpDataSend(byte[] message, IPEndPoint to)
    {
        if (_server is null)
        {
            Log.Warn($"Can't send to {to.Address}, this Child SA has no UDP server connection");
            return;
        }
        
        MessagesOut++;
        DataOut += (ulong)message.Length;
        
        _server.SendRaw(message, to);

        _msgIdOut++;
    }

    private void CaptureTraffic(byte[] plain, string direction)
    {
        if (!Settings.CaptureTraffic) return;
        
        File.WriteAllText(Settings.FileBase + $"IPv4_{_captureNumber}_{direction}.txt", Bit.Describe($"ipv4_{_captureNumber}_{direction}", plain));
        _captureNumber++;
    }

    /// <summary>
    /// Returns true if any of the ranges declared by the gateway
    /// include the supplied target address
    /// </summary>
    public bool ContainsIp(IpV4Address target)
    {
        if (_trafficSelect is null)
        {
            Log.Debug("ChildSA has no traffic select");
            return false;
        }

        if (_trafficSelect.Selectors.Count < 1)
        {
            Log.Debug("ChildSA was provided a traffic select, but it is empty");
            return false;
        }

        foreach (var selector in _trafficSelect.Selectors)
        {
            Log.Trace($"    comparing {target.AsString} to {selector.Describe()}");
            if (selector.Contains(target))
            {
                Log.Trace("    found!");
                return true;
            }
            Log.Trace("    does not match");
        }
        Log.Trace("    no matches found");
        return false;
    }

    /// <summary>
    /// Send a single ICMP ping request to the target
    /// </summary>
    public void SendPing(IpV4Address target)
    {
        var icmp = new IcmpPacket
        {
            MessageType = IcmpType.EchoRequest,
            MessageCode = 0,
            Checksum = 0,
            PingIdentifier = 0,
            PingSequence = 0,
            Payload = Array.Empty<byte>()
        };

        var checksum = IpChecksum.CalculateChecksum(ByteSerialiser.ToBytes(icmp));
        icmp.Checksum = checksum;
        
        var selector = Settings.LocalTrafficSelector.ToSelector();

        var icmpData = ByteSerialiser.ToBytes(icmp);
        var ipv4Reply = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + icmpData.Length,
            PacketId = RandomPacketId(),
            Flags = IpV4HeaderFlags.DontFragment,
            FragmentIndex = 0,
            Ttl = 64,
            Protocol = IpV4Protocol.ICMP,
            Checksum = 0,
            Source = new IpV4Address(selector.StartAddress),
            Destination = target,
            Options = Array.Empty<byte>(),
            Payload = icmpData
        };
        
        ipv4Reply.UpdateChecksum();

        Log.Info("    Sending ping...");
        var encryptedData = WriteSpe(ipv4Reply);
        UdpDataSend(encryptedData, Gateway.MakeEndpoint(4500));
        _pingTimer.Restart();
    }

    public string Describe() => $"Child SA, ({Bit.HexString(_spiIn)} / {Bit.HexString(_spiOut)}) Gateway={Gateway.AsString}, ParentSession={Parent?.LocalSpi:x16}";
}