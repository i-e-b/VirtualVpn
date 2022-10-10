using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using SkinnyJson;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;
using VirtualVpn.TlsWrappers;
using VirtualVpn.Web;

// ReSharper disable BuiltInTypeReferenceStyle

namespace VirtualVpn;

public interface ISessionHost
{
    void AddChildSession(ChildSa childSa);
    void RemoveChildSession(params uint[] spis);
    void RemoveSession(bool wasRemoteRequest, params ulong[] spis);
}

public class VpnServer : ISessionHost, IDisposable
{
    private const int NonEspHeader = 0; // https://docs.strongswan.org/docs/5.9/features/natTraversal.html

    // Session management
    private readonly Thread _eventPumpThread;
    private readonly UdpServer _server;
    private readonly Dictionary<UInt64, VpnSession> _sessions = new();
    private readonly Dictionary<UInt32, ChildSa> _childSessions = new();
    
    // Internal counts
    private volatile bool _running;
    private long _espCount;
    private int _messageCount;
    
    // Stats stuff
    private readonly EspTimedEvent _statsTimer;
    private ulong _sessionsStarted;
    private readonly ISet<IpV4Address> _alwaysConnections = new HashSet<IpV4Address>();

    public VpnServer()
    {
        try
        {
            _server = new UdpServer(IkeResponder, SpeResponder);
        }
        catch (SocketException ex)
        {
            Log.Critical("Could not start VirtualVPN UDP server. Do you have other VPN software running? Try 'ipsec stop'");
            Log.Error("Failed to start core network interface", ex);
            throw;
        }

        _statsTimer = new EspTimedEvent(StatsEvent, Settings.StatsFrequency);
        _eventPumpThread = new Thread(EventPumpLoop) { IsBackground = true };
    }

    /// <summary>
    /// Run the VirtualVPN software
    /// </summary>
    /// <param name="args">Optional commands in the form "CmdName=Arg1,Arg2"</param>
    public void Run(IEnumerable<string>? args)
    {
        Log.Debug("Setup");
        Json.DefaultParameters.EnableAnonymousTypes = true;
        Console.CancelKeyPress += StopRunning;

        _running = true;
        
        _server.Start();
        _eventPumpThread.Start();

        if (args is not null)
        {
            Thread.Sleep(250);
            RunCommandArgs(args);
        }

        while (_running)
        {
            // wait for local commands
            string? cmd;
            try
            {
                cmd = Console.ReadLine();
            }
            catch (Exception ex)
            {
                Log.Info($"Can't read command inputs: {ex.Message}");
                Thread.Sleep(2500);
                continue;
            }

            try
            {
                var prefix = Min2(cmd?.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
                Console.WriteLine($"CMD: `{prefix[0]}` ({prefix[1]})\r\n");

                HandleCommands(prefix);
            }
            catch (Exception ex)
            {
                Log.Error("Failure in interactive command 'cmd'", ex);
            }
        }
    }


    /// <summary>
    /// Runs a set of command-line arguments against
    /// the <see cref="HandleCommands"/> call.
    /// Each argument is a command in the form "CmdName=Arg1,Arg2"
    /// </summary>
    public void RunCommandArgs(IEnumerable<string> args)
    {
        foreach (var arg in args)
        {
            try
            {
                var cmd = arg.Split('=', ',');
                HandleCommands(cmd);
            }
            catch (Exception ex)
            {
                Log.Error($"Argument '{arg}' failed", ex);
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

    public void RemoveSession(bool wasRemoteRequest, params ulong[] spis)
    {
        var removedCount = 0;

        foreach (var spi in spis)
        {
            if (!_sessions.ContainsKey(spi)) continue;

            // Unhook the old session
            var session = _sessions[spi];
            var removed = _sessions.Remove(spi);
            Log.Info($"Session {spi:x} removed. It was connected to {session.Gateway}");

            if (removed) removedCount++;
            
            // If this is a persistent session ended from elsewhere, start it back up
            if (wasRemoteRequest && Settings.ReEstablishOnDisconnect)
            {
                Log.Info($"Attempting to restart session with {session.Gateway}");
                StartVpnSession(session.Gateway);
            }
        }


        if (removedCount < 1)
        {
            Log.Warn($"No matching session found in set: {string.Join(", ", spis.Select(i=>i.ToString("x")))}");
        }

    }

    public void RemoveChildSession(params uint[] spis)
    {
        var removedCount = 0;

        foreach (var spi in spis)
        {
            if (!_childSessions.ContainsKey(spi)) continue;

            // Unhook the old session
            var session = _childSessions[spi];
            var removed = _childSessions.Remove(spi);
            Log.Info($"Child session {spi:x} removed. It was connected to {session.Gateway}");

            if (removed) removedCount++;
        }

        if (removedCount < 1)
        {
            Log.Warn($"No matching child session found in set: {string.Join(", ", spis.Select(i=>i.ToString("x")))}");
        }
    }
    
    public HttpProxyResponse MakeProxyCall(HttpProxyRequest request)
    {
        try
        {
            var uri = new Uri(request.Url, UriKind.Absolute);
            
            var target = IpV4Address.FromString(uri.Host);
            var proxyAddress = IpV4Address.FromString(request.ProxyLocalAddress);
            var tunnel = FindTunnelTo(target);
            
            var useTls = uri.Scheme == "https";
            Log.Info($"Starting connection to {uri}, useTls={useTls}");
            
            using var apiSide = new TlsHttpProxyCallAdaptor(request, useTls);
            using var channel = tunnel.OpenTcpSession(target, uri.Port, proxyAddress, apiSide);
            
            var timeout = new Stopwatch();
            timeout.Start();

            while (
                apiSide.Connected // this will be flipped when the Tcp connection is over
                && timeout.Elapsed < TimeSpan.FromSeconds(30) // timeout -- needs to be quite long as our SSL/TLS is slow
                )
            {
                if (!channel.EventPump())
                {
                    Thread.Sleep(50);
                }
                var outgoingDataReady = channel.SocketThroughTunnel.BytesOfSendDataWaiting;
                if (outgoingDataReady > 0)
                {
                    Log.Trace($"Virtual socket has {outgoingDataReady} bytes waiting");
                }
            }

            if (apiSide.Connected) Log.Warn("Proxy call ended due to TIMEOUT");
            else Log.Trace("Ending Proxy call at end of document");

            apiSide.Close();
            channel.Close();

            // make sure we stop pumping the connection
            tunnel.ReleaseConnection(channel.SelfKey);
            
            return apiSide.GetResponse();
        }
        catch (Exception ex)
        {
            return new HttpProxyResponse{
                Success = false,
                ErrorMessage = ex.ToString()
            };
        }
    }

    /// <summary>
    /// Handle control argument from either std-in, or from the command line
    /// </summary>
    /// <param name="command">command and arguments</param>
    private void HandleCommands(string[] command)
    {
        switch (command[0])
        {
            case "crypto": // very detailed logging, plus crypto details (INSECURE)
            {
                Log.SetLevel(LogLevel.Crypto);
                return;
            }
            case "trace": // very detailed logging
            {
                Log.SetLevel(LogLevel.Trace);
                return;
            }
            case "debug": // detailed logging
            {
                Log.SetLevel(LogLevel.Debug);
                return;
            }
            case "info": // informational logging
            {
                Log.SetLevel(LogLevel.Info);
                return;
            }
            case "warn": // informational logging
            {
                Log.SetLevel(LogLevel.Warning);
                return;
            }

            case "quit": // exit VirtualVPN session
            {
                _running = false;
                return;
            }

            case "kill": // stop an association
            {
                KillSessionBySpi(command[1]);
                return;
            }
            case "list": // list open SAs
            {
                ListGateways();
                return;
            }
            case "start": // connect to a gateway and open a new SA
            {
                try
                {
                    TryStartVpnIfNotAlreadyConnected(command[1]);
                }
                catch (Exception ex)
                {
                    Log.Error("Could not start VPN connection: ", ex);
                }

                return;
            }
            case "always": // try to keep a connection up at all times
            {
                try
                {
                    var target = IpV4Address.FromString(command[1]);//TryStartVpnIfNotAlreadyConnected(command[1]);
                    RegisterAlways(target);
                }
                catch (Exception ex)
                {
                    Log.Error("Could not start VPN connection: ", ex);
                }

                return;
            }
            case "capture":
            {
                Settings.CaptureTraffic = !Settings.CaptureTraffic;
                Console.WriteLine($"Traffic capture now {(Settings.CaptureTraffic ? "on" : "off")}. Capture location '{Settings.FileBase}'");
                break;
            }
            case "airlift":
            {
                Settings.RunAirliftSite = !Settings.RunAirliftSite;
                Console.WriteLine($"Airlift site toggled {(Settings.RunAirliftSite?"on":"off")}. It may take a few seconds to process.");
                break;
            }
            case "psk":
            {
                Settings.PreSharedKeyString = command[1]; // this should be on a per-gateway basis
                Console.WriteLine("Pre-shared key updated. This will affect NEW sessions only.");
                break;
            }
            case "ping":
            {
                try { DoPing(command); }
                catch (Exception ex) { Log.Error("Failed ping", ex); }
                break;
            }
            case "save": {
                try { SaveSettings(command); }
                catch (Exception ex) { Log.Error("Failed to save settings", ex); }
                break;
            }
            case "load": {
                try { LoadSettings(command); }
                catch (Exception ex) { Log.Error("Failed to load settings", ex); }
                break;
            }
            case "wget":
            {
                var parts = command[1].Split(' ', StringSplitOptions.TrimEntries);
                if (parts.Length != 2)
                {
                    Console.WriteLine($"Expected IP and URL. Got {parts.Length} parts (should be 2)");
                    break;
                }
                
                var uri = new Uri(parts[1], UriKind.Absolute);

                // Kick off a proxy call as if the external API was hit.
                var request= new HttpProxyRequest
                {
                    Url = parts[1],
                    Headers = {
                        { "Host", uri.Host },
                        {"Accept", "*/*"},
                        {"Content-Length", "0"}
                    },
                    HttpMethod = "GET",
                    ProxyLocalAddress = parts[0]
                };
                var response = MakeProxyCall(request);
                
                Console.WriteLine(response.Describe());
                break;
            }
            default:
                Console.WriteLine("Known commands:");
                Console.WriteLine("    Logging:");
                Console.WriteLine("        warn, info, debug, trace ... crypto (INSECURE)");
                Console.WriteLine("    Connection:");
                Console.WriteLine("        list, kill [sa-id],");
                Console.WriteLine("        start [gateway], always [gateway],");
                Console.WriteLine("        psk [psk-string]");
                Console.WriteLine("    Testing:");
                Console.WriteLine("        ping [ip-address],");
                Console.WriteLine("        wget [fake-ip] [target-url]");
                Console.WriteLine("    General:");
                Console.WriteLine("        quit, capture,");
                Console.WriteLine("        load [file-name], save [file-name]");
                return;
        }
    }
    
    /// <summary>
    /// Writes server statistics to console
    /// </summary>
    private void StatsEvent(EspTimedEvent obj)
    {
        _statsTimer.Reset();
        if ( ! Log.IncludeInfo) return;
        
        GC.Collect();
        var gc = GC.GetGCMemoryInfo();
        using var myProc = Process.GetCurrentProcess();
        var tCount = myProc.Threads.Count;
        var allMem = myProc.PrivateMemorySize64;

        var expectedThreads = TlsUnwrap.ClosedAdaptors * 2;
        var unexpectedThreads = tCount - expectedThreads;
        
        var sb = new StringBuilder();

        sb.Append($"Statistics:\r\n\r\nSessions={_sessions.Count} active, {_sessionsStarted} started;"); 
        sb.Append($"\r\nTotal data in={Bit.Human(_server.TotalIn)}, out={Bit.Human(_server.TotalOut)}");
        sb.Append($"\r\nMemory: process={Bit.Human(allMem)}, GC.Total={Bit.Human(GC.GetTotalMemory(false))}, GC.Heap={Bit.Human(gc.HeapSizeBytes)}, Avail={Bit.Human(gc.TotalAvailableMemoryBytes)}");
        sb.Append($"\r\nActive threads={tCount}, tls wrappers running={TlsUnwrap.RunningThreads}, tls waiting dispose={expectedThreads}, unaccounted={unexpectedThreads}");
        
        sb.Append("\r\nChild sessions:\r\n");
        foreach (var childSa in _childSessions.Values)
        {
            sb.Append($"    Gateway={childSa.Gateway}, Spi-in={childSa.SpiIn:x}, Spi-out={childSa.SpiOut:x}\r\n");
            sb.Append($"        Parent:   spi={childSa.Parent?.LocalSpi:x}, state={childSa.Parent?.State.ToString() ?? "<orphan>"}\r\n");
            sb.Append($"        Messages: in={childSa.MessagesIn}, out={childSa.MessagesOut}\r\n");
            sb.Append($"        Data:     in={Bit.Human(childSa.DataIn)}, out={Bit.Human(childSa.DataOut)}\r\n");
            sb.Append($"        Sessions: active={childSa.ActiveSessionCount}, parked={childSa.ParkedSessionCount}\r\n");
        }
        sb.Append("\r\n");
        
        Console.WriteLine(sb.ToString());
    }

    /// <summary>
    /// Register a target to be always connected
    /// </summary>
    private void RegisterAlways(IpV4Address target)
    {
        if (_alwaysConnections.Contains(target)) return;
        
        _alwaysConnections.Add(target);
    }

    private void KillSessionBySpi(string spiStr)
    {
        var ok = ulong.TryParse(spiStr, NumberStyles.HexNumber, null, out var spi);
        if (!ok)
        {
            Console.WriteLine($"Could not interpret '{spiStr}' as a hex number. Use 'list' to get current sessions.");
            return;
        }

        // Try to find an IKE/ESP session
        foreach (var vpnSession in _sessions)
        {
            if (vpnSession.Key != spi) continue;
            
            Console.WriteLine($"Found session with {vpnSession.Value.Gateway}, ending now.");
            var canCloseProperly = vpnSession.Value.EndConnectionWithPeer();
            
            // if it's a half-open or junk connection, just ditch it
            if (!canCloseProperly) _sessions.Remove(vpnSession.Key);

            return;
        }
        
        // Otherwise, try to find just the ESP session
        foreach (var espSession in _childSessions)
        {
            if (espSession.Key != spi) continue;
            
            Console.WriteLine($"Found ChildSA (ESP session) with {espSession.Value.Gateway}, ending now.");
            var parent = espSession.Value.Parent;

            if (parent is null)
            {
                Log.Warn("Session was orphaned!");
            }
            else
            {
                Log.Info("Ending session");
                var canCloseProperly = parent.EndConnectionWithPeer();
                
                // if it's a half-open or junk connection, just ditch it
                if (!canCloseProperly) _childSessions.Remove(espSession.Key);
            }

            return;
        }
        
        Console.WriteLine($"Could not find an active session with SPI {spi:x}. Use 'list' to get current sessions.");
    }

    private void LoadSettings(string[] prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix[1])) throw new Exception("Invalid file name for load");
        if (!File.Exists(prefix[1])) throw new Exception($"File not found: {prefix[1]}; Base directory={Environment.CurrentDirectory}");
        
        var json = File.ReadAllText(prefix[1]);
        Json.DefrostInto(typeof(Settings), json);
        
        Log.Info($"Loaded: {json}");
        Program.RestartHttpServer();
    }

    private void SaveSettings(string[] prefix)
    {
        var json = Json.Freeze(typeof(Settings));
        
        if (string.IsNullOrWhiteSpace(prefix[1]))
        {
            Log.Info($"Not stored (no file name given). Current settings:\r\n{json}");
            return;
        }

        File.WriteAllText(prefix[1], json);
        Log.Info($"Stored: {json}");
    }

    private void DoPing(string[] prefix)
    {
        // First, try to find a VPN session that includes the target IP address
        var target = IpV4Address.FromString(prefix[1]);

        var matchingSessions = _childSessions.Values.Where(s => s.ContainsIp(target)).ToList();
        if (matchingSessions.Count > 1) HandleSessionConflict(matchingSessions);
        if (matchingSessions.Count < 1) throw new Exception("No session claims this IP address (not found)");
        
        var session = matchingSessions[0];
        session.SendPing(target);
    }

    private static void HandleSessionConflict(List<ChildSa> matchingSessions)
    {
        Log.Warn("More than one session claims this IP address (conflict). Will use first in list.");
        Log.Info($"Conflicting sessions:\r\n\r\n{string.Join("\r\n", matchingSessions.Select(s=>s.Describe()))}");
    }

    private void ListGateways()
    {
        Console.WriteLine("\r\nEstablished connections:");
        foreach (var session in _childSessions)
        {
            var p = session.Value.Parent;
            var ikeDesc = p is null
                ? "(orphaned)"
                : $"from session {p.LocalSpi:x}. State={p.State.ToString()}, Last touch={p.LastTouchTimer.Elapsed}. Initiated={(p.WeStarted ? "here" : "remotely")}";
            Console.WriteLine($"    {session.Value.Gateway} [{session.Key:x}] {ikeDesc}");
            Console.WriteLine("        "+string.Join("\r\n        ",session.Value.ListTcpSessions()));
        }
    }

    private IpV4Address? TryStartVpnIfNotAlreadyConnected(string gatewayAddress)
    {
        // Assume gateway address is IPv4 decimals for now.
        Console.WriteLine($"Requested connection to [{gatewayAddress}], searching for existing connections");
        
        var requestedGateway = IpV4Address.FromString(gatewayAddress);
        
        // first, see if we've already got a connection up:
        foreach (var childSession in _childSessions)
        {
            if (childSession.Value.Gateway == requestedGateway)
            {
                Console.WriteLine($"A VPN session is already open with {requestedGateway} as {childSession.Key:x}.\r\nTry 'kill {childSession.Key:x}' if you want to restart");
                return null;
            }
        }
        
        // next, see if we've already got a connection pending:
        foreach (var vpnSession in _sessions)
        {
            if (vpnSession.Value.Gateway == requestedGateway && vpnSession.Value.IsStarting())
            {
                Console.WriteLine($"A VPN session is in progress with {requestedGateway} as {vpnSession.Key:x}.\r\nTry 'kill {vpnSession.Key:x}' if you want to restart");
                return null;
            }
        }
        
        Console.WriteLine("Starting contact with gateway");
        StartVpnSession(requestedGateway);
        return requestedGateway;
    }

    /// <summary>
    /// Start a new session with a remote gateway.
    /// </summary>
    private void StartVpnSession(IpV4Address gateway)
    {
        // Start a new IKEv2 session, with an ID of our choosing.
        // Add that to the ongoing sessions (we might need to map
        // both sides of SPI on session lookup?)
        
        var newSession = new VpnSession(gateway, _server, this, weAreInitiator:true, 0);
        Log.Debug($"Starting new session with SPI {newSession.LocalSpi:x16}");
        _sessions.Add(newSession.LocalSpi, newSession);
        _sessionsStarted++;
        
        newSession.RequestNewSession(gateway.MakeEndpoint(port:500));
    }

    /// <summary>
    /// Return at least two items from the array,
    /// even if the array is null or shorter than
    /// two items.
    /// </summary>
    private string[] Min2(string[]? split)
    {
        if (split is null) return new string[2];
        if (split.Length <= 0) return new string[2];
        if (split.Length == 1) return new[]{split[0], ""};
        return split;
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
        Log.Info($"Got a 500 packet, {data.Length} bytes");

        if (data.Length == 1)
        {
            Log.Warn("Received a keep-alive packet during IKE process. This probably means there is a network problem, or a fault in the handshake process.");
            return;
        }

        IkeSessionResponder(data, sender, sendZeroHeader: false);
    }

    private void IkeSessionResponder(byte[] data, IPEndPoint sender, bool sendZeroHeader)
    {
        if (Settings.CaptureTraffic)
        {
            var name = Settings.FileBase + $"IKEv2-{_messageCount++}_Port-{sender.Port}_IKE.bin";
            File.WriteAllBytes(name, data);
        }

        // read the message to figure out session data
        var ikeMessage = IkeMessage.FromBytes(data, 0);

        Log.Info($"Got a 500 packet, {data.Length} bytes, ex={ikeMessage.Exchange}");
        Log.Debug($"IKE flags {ikeMessage.MessageFlag.ToString()}, message id={ikeMessage.MessageId}, first payload={ikeMessage.FirstPayload.ToString()}");

        if (ikeMessage.Exchange == ExchangeType.IDENTITY_1) // start of an IkeV1 session
        {
            Log.Warn("    Message is for IKEv1. Not supported, not replying");
            return;
        }

        if (_sessions.ContainsKey(ikeMessage.SpiI))
        {
            var session = _sessions[ikeMessage.SpiI];
            if (session.WeStarted)
            {
                Log.Info($"    it's for an existing session we started {ikeMessage.SpiI:x16} (us) => {ikeMessage.SpiR:x16} (them)");
            }
            else
            {
                Log.Info($"    it's for an existing session started by the peer {ikeMessage.SpiI:x16} (them) => {ikeMessage.SpiR:x16} (us)");
            }

            // Pass message to existing session
            session.HandleIke(ikeMessage, sender, sendZeroHeader);
            return;
        }

        Log.Info($"    it's for a new session  {ikeMessage.SpiI:x16} => {ikeMessage.SpiR:x16}");
            
        // Start a new session and store it, keyed by the initiator id
        var newSession = new VpnSession(IpV4Address.FromEndpoint(sender), _server, this, weAreInitiator:false, ikeMessage.SpiI);
        _sessions.Add(ikeMessage.SpiI, newSession);
        _sessionsStarted++;
            
        // Pass message to new session
        newSession.HandleIke(ikeMessage, sender, sendZeroHeader); 
    }

    /// <summary>
    /// Responds to port 4500 traffic
    /// </summary>
    private void SpeResponder(byte[] data, IPEndPoint sender)
    {
        if (data.Length < 1) return; // junk message

        Log.Trace($"Got a 4500 packet, {data.Length} bytes");

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
        var header = Bit.ReadInt32(data, ref idx); // if not zero, it's an ESP packet

        // If the IKE header is there, pass back to the ike handler.
        // We strip the padding off, and pass a flag to say it should be sent with a response
        if (header == NonEspHeader)
        {
            Log.Trace("    SPI zero on 4500 -- sending to 500 (IKE) responder");
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
            Log.Warn($"    Unknown session: 0x{spi:x8} -- not replying");
            Log.Debug("    Expected sessions=", ListKnownSpis);
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
    }

    private IEnumerable<string> ListKnownSpis()
    {
        foreach (var key in _sessions.Keys)
        {
            yield return $"IKE {key:x16}; ";
        }

        foreach (var child in _childSessions)
        {
            yield return $"ESP {child.Key:x8} (in={child.Value.SpiIn:x8}, out={child.Value.SpiOut:x8}); ";
        }
    }

    /// <summary>
    /// This calls the "EventPump" method on all VpnSession
    /// and ChildSA objects that are currently active.
    ///
    /// This is our co-operative multi-tasking setup that
    /// doesn't require us to juggle threads.
    /// This is done with the expectation that we will
    /// usually have 1 connected gateway at a time.
    /// </summary>
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
                var goFaster = false;
                //Log.Trace("Triggering event pump");

                // Pump sessions (timing and connection)
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

                // Pump Child SAs (tunnel data)
                foreach (var childSa in _childSessions.Values)
                {
                    try
                    {
                        goFaster |= childSa.EventPump();
                    }
                    catch (Exception ex)
                    {
                        Log.Error("Event pump failure, ChildSA", ex);
                    }
                }
                
                // Ensure 'always' connections are up
                RestartAlwaysConnectedGatewaysIfDown();

                // Display stats
                _statsTimer.TriggerIfExpired();
                
                // Wait before looping, unless any of the ChildSA are active,
                // in which case we go full speed.
                if (!goFaster) Thread.Sleep(Settings.EventPumpRate);
                else Thread.Sleep(1);

                // Go slower when running trace logging
                if (Log.IsTracing) { Thread.Sleep(Settings.EventPumpRate); }

                // If there aren't any connections, run even slower
                if (_childSessions.Count < 1) Thread.Sleep(Settings.EventPumpRate);
            }
            catch (Exception ex)
            {
                Log.Warn($"Outer event pump failure: {ex.Message}"); // most likely a thread conflict?
                Thread.Sleep(Settings.EventPumpRate);
            }
        }
    }

    private void RestartAlwaysConnectedGatewaysIfDown()
    {
        foreach (var requiredGateway in _alwaysConnections)
        {
            var found = false;

            // first, see if we've already got a connection up:
            foreach (var childSession in _childSessions)
            {
                if (childSession.Value.Gateway != requiredGateway) continue;
                found = true;
                break;
            }

            // next, see if we've already got a connection pending:
            foreach (var vpnSession in _sessions)
            {
                if (vpnSession.Value.Gateway != requiredGateway || !vpnSession.Value.IsStarting()) continue;
                found = true;
                break;
            }

            if (found) continue;

            // Nothing found. Start again
            StartVpnSession(requiredGateway);
        }
    }

    private ChildSa FindTunnelTo(IpV4Address target)
    {
        foreach (var childSa in _childSessions.Values)
        {
            if (childSa.ContainsIp(target)) return childSa;
        }
        throw new Exception($"No open SA to '{target.AsString}' exists.");
    }
}