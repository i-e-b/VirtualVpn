using System.Net;
using SkinnyJson;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;

// ReSharper disable BuiltInTypeReferenceStyle

namespace VirtualVpn;

public class VpnServer : IDisposable
{
    private const int NonEspHeader = 0; // https://docs.strongswan.org/docs/5.9/features/natTraversal.html

    private readonly Thread _eventPumpThread;
    private readonly UdpServer _server;
    private readonly Dictionary<UInt64, VpnSession> _sessions = new();
    private readonly Dictionary<UInt32, ChildSa> _childSessions = new();
    private volatile bool _running;
    private long _espCount;

    public VpnServer()
    {
        _server = new UdpServer(IkeResponder, SpeResponder);
        _eventPumpThread = new Thread(EventPumpLoop){IsBackground = true};
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

        _running = true;
        
        _server.Start();
        _eventPumpThread.Start();


        while (_running)
        {
            // wait for local commands
            var cmd = Console.ReadLine();
            Console.Write($"CMD: `{cmd}`");

            switch (cmd)
            {
                case "loud":
                {
                    Log.SetLevel(LogLevel.Debug);
                    break;
                }
                case "less":
                {
                    Log.SetLevel(LogLevel.Info);
                    break;
                }
                default:
                    Console.WriteLine("Known commands: loud, less;");
                    break;
            }
        }
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
            _server.SendRaw(data, sender);
            return;
        }

        if (data.Length < 8)
        {
            Log.Warn($"    Malformed SPE/ESP from {sender.Address}. Not responding");
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
        // This is 32 bits, and not the 64 bits of the IKE SPI.
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

        try
        {
            // check, decrypt, route, etc.
            childSa.HandleSpe(data, sender);
        }
        catch (Exception ex)
        {
            Log.Warn($"Failed to handle SPE message from {sender.Address}: {ex.Message}");
            Log.Debug(ex.ToString());
        }
        
        Log.Debug("    Looks like a fully valid message. Other side will expect a reply.");
    }

    private void EventPumpLoop()
    {
        while (!_running)
        {
            Log.Debug("Event pump waiting for run flag");
            Thread.Sleep(Settings.EventPumpRate);
        }

        while (_running)
        {
            try
            {
                Thread.Sleep(Settings.EventPumpRate);
                Log.Debug("Triggering event pump");

                foreach (var session in _sessions.Values)
                {
                    try
                    {
                        session.EventPump();
                    }
                    catch (Exception ex)
                    {
                        Log.Error("Event pump failure, VPN", ex);
                    }
                }

                foreach (var childSa in _childSessions.Values)
                {
                    try
                    {
                        childSa.EventPump();
                    }
                    catch (Exception ex)
                    {
                        Log.Error("Event pump failure, ChildSA", ex);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warn($"Outer event pump failure: {ex.Message}"); // most likely a thread conflict
            }
        }
    }
}