using System.Net;
using RawSocketTest.Helpers;
using SkinnyJson;
// ReSharper disable BuiltInTypeReferenceStyle

namespace RawSocketTest;

public class VpnServer : IDisposable
{
    private const int NonEspHeader = 0; // https://docs.strongswan.org/docs/5.9/features/natTraversal.html

    private readonly UdpServer _server;
    private readonly Dictionary<UInt64, VpnSession> _sessions = new();
    private readonly Dictionary<UInt32, ChildSa> _childSessions = new();
    private volatile bool _running;
    private long _espCount;

    public VpnServer()
    {
        _server = new UdpServer(IkeResponder, SpeResponder);
    }

    public void Run()
    {
        Log.Debug("Setup");
        Json.DefaultParameters.EnableAnonymousTypes = true;
        Console.CancelKeyPress += StopRunning;

// Use Gerty for testing. Run "JustListen" to check your connection is working.
// You may need to do lots of firewall poking and NAT rules.
// Switch on ipsec on Gerty (`ipsec restart`), make sure there is a ruleset for the test PC.

//var target = new IPEndPoint(new IPAddress(new byte[]{197,250,65,132}), 500); // M-P
//var target = new IPEndPoint(new IPAddress(new byte[] { 159, 69, 13, 126 }), 500); // Gerty

        _server.Start();
        _running = true;


        while (_running)
        {
            // wait for local commands
            var cmd = Console.ReadLine();
            Console.Write($"CMD: `{cmd}`");

            if (cmd == "ips")
            {
                Console.WriteLine("Notifying of IPs...");
                foreach (var (key, vpnSession) in _sessions)
                {
                    Console.Write($"    {key}");
                    vpnSession.NotifyIpAddresses();
                    Console.WriteLine(" - done");
                }
                Console.WriteLine("notifying done.");
            }
        }
    }

    private void StopRunning(object? sender, ConsoleCancelEventArgs e)
    {
        _running = false;
    }


    /// <summary>
    /// Responds to port 500 traffic
    /// </summary>
    private void IkeResponder(byte[] data, IPEndPoint sender)
    {
        // write capture to file for easy testing
        //var name = Settings.FileBase + $"IKEv2-{_messageCount}_Port-{sender.Port}_IKE.bin";
        //File.WriteAllBytes(name, data);
        Log.Info($"Got a 500 packet, {data.Length} bytes");
        
        IkeSessionResponder(data, sender, sendZeroHeader: false);
    }

    private void IkeSessionResponder(byte[] data, IPEndPoint sender, bool sendZeroHeader)
    {
        // read the message to figure out session data
        var ikeMessage = IkeMessage.FromBytes(data, 0);

        Log.Info($"Got a 500 packet, {data.Length} bytes, ex={ikeMessage.Exchange}");

        if (ikeMessage.Exchange == ExchangeType.IDENTITY_1) // start of an IkeV1 session
        {
            Log.Warn("    Message is for IKEv1. Not supported, not replying");
            return;
        }

        if (_sessions.ContainsKey(ikeMessage.SpiI))
        {
            Log.Info($"    it's for an existing session started by the peer {ikeMessage.SpiI:x16} => {ikeMessage.SpiR:x16}");
            
            // Pass message to existing session
            _sessions[ikeMessage.SpiI].HandleIke(ikeMessage, sender, sendZeroHeader);
            return;
        }

        if (_sessions.ContainsKey(ikeMessage.SpiR))
        {
            Log.Info($"    it's for an existing session we started {ikeMessage.SpiI:x16} => {ikeMessage.SpiR:x16}");
            
            // Pass message to existing session
            _sessions[ikeMessage.SpiR].HandleIke(ikeMessage, sender, sendZeroHeader);
            return;
        }

        Log.Info($"    it's for a new session  {ikeMessage.SpiI:x16} => {ikeMessage.SpiR:x16}");
            
        // Start a new session and store it, keyed by the initiator id
        var newSession = new VpnSession(_server, this, ikeMessage.SpiI);
        _sessions.Add(ikeMessage.SpiI, newSession);
            
        // Pass message to new session
        newSession.HandleIke(ikeMessage, sender, sendZeroHeader); 
    }

    /// <summary>
    /// Responds to port 4500 traffic
    /// </summary>
    private void SpeResponder(byte[] data, IPEndPoint sender)
    {
        if (data.Length < 1) return; // junk message

        Log.Info($"Got a 4500 packet, {data.Length} bytes");

        // Check for keep-alive ping?
        if (data.Length < 4 && data[0] == 0xff)
        {
            Log.Info("    Looks like a keep-alive ping. Sending pong");
            _server.SendRaw(data, sender, out _);
            return;
        }
        
        // Check for "IKE header" (prefix of 4 zero bytes)
        var idx = 0;
        var header = Bit.ReadInt32(data, ref idx); // not quite sure what this is about

        // If the IKE header is there, pass back to the ike handler.
        // We strip the padding off, and pass a flag to say it should be sent with a response
        if (header == NonEspHeader) // start session?
        {
            Log.Info("    SPI zero on 4500 -- sending to 500 (IKE) responder");
            var offsetData = data.Skip(4).ToArray();
            IkeSessionResponder(offsetData, sender, sendZeroHeader: true);
            return;
        }

        // There is no Non-ESP marker, so the first 4 bytes are the ESP "Security Parameters Index".
        // This is 32 bits, and not the 64 bits of the IKE SPI?
        // (see https://docs.strongswan.org/docs/5.9/features/natTraversal.html , https://en.wikipedia.org/wiki/Security_Parameter_Index )
        // "The SPI (as per RFC 2401) is a required part of an Ipsec Security Association (SA)"
        // https://en.wikipedia.org/wiki/IPsec has notes and diagrams of the ESP headers
        // ESP uses different encryption modes compared to IKEv2
        idx = 0;
        var spi = Bit.ReadUInt32(data, ref idx);

        if (Settings.CaptureTraffic)
        {
            File.WriteAllText(Settings.FileBase+$"ESP_{_espCount}.txt", Bit.Describe($"esp_{_espCount}", data));
            _espCount++;
        }

        // reject unknown sessions
        if (!_childSessions.ContainsKey(spi))
        {
            Log.Warn($"    Unknown session: 0x{spi:x16} -- not replying");
            return;
        }

        // if we get here, we have a new message (with encryption) for an existing session
        var childSa = _childSessions[spi];
        idx = 4;
        var seq = Bit.ReadUInt32(data, ref idx);
        Log.Debug($"    Packet has sequence #{seq}");
        if (childSa.OutOfSequence(seq))
        {
            Log.Warn($"    Received out of sequence packet: {seq} -- not replying");
            return;
        }
        
        // TODO: HMAC-SHA2-256-96 fix ?  See pvpn/server.py:411
        
        // verify the checksum
        var ok = childSa.VerifyMessage(data);
        if (!ok)
        {
            Log.Warn($"    Received packet with bad checksum: {seq} -- not replying");
            return;
        }
        
        // looks ok. Step the sequence number forward
        childSa.IncrementSequence(seq);

        // do decrypt, route, etc.
        childSa.HandleSpe(data, sender);
        
        Log.Debug("    Looks like a fully valid message. Other side will expect a reply.");
    }



    public void Dispose()
    {
        _server.Dispose();
        GC.SuppressFinalize(this);
    }

    public void AddChildSession(ChildSa childSa)
    {
        _childSessions.Add(childSa.SpiIn, childSa);
    }

    public void RemoveSession(ulong spi)
    {
        if (_sessions.ContainsKey(spi)) _sessions.Remove(spi);
    }

    public void RemoveChildSession(uint spi)
    {
        if (_childSessions.ContainsKey(spi)) _childSessions.Remove(spi);
    }
}