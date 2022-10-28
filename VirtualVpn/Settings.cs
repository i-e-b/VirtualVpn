using VirtualVpn.Enums;
using VirtualVpn.EspProtocol.Payloads.PayloadSubunits;
using VirtualVpn.Helpers;
// ReSharper disable FieldCanBeMadeReadOnly.Global
// ReSharper disable ConvertToConstant.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global
#pragma warning disable CA2211 // constants should not be public

namespace VirtualVpn;

public static class Settings
{
    #region VPN establishment
    /// <summary>
    /// PSK for session establishment. This MUST be shared with the
    /// remote gateway.
    /// </summary>
    public static string PreSharedKeyString = "ThisIsForTestOnlyDontUse";
    
    /// <summary>
    /// If true, and the remote peer disconnects, VirtualVPN will try to restart the
    /// connection.
    /// <p></p>
    /// If false, or the connection was ended locally, we will not try to re-establish
    /// the connection, but we will accept remote connections.
    /// </summary>
    public static bool ReEstablishOnDisconnect = true;
    
    /// <summary>
    /// A description of the network on our side of the VPN tunnel.
    /// This must match the expectations of the other side, or the connection will fail.
    /// </summary>
    public static TrafficSelectorSetting LocalTrafficSelector { get; set; } = new()
    {
        StartPort = 0,
        EndPort = 65535,
        StartAddress = "55.55.0.0",
        EndAddress = "55.55.255.255"
    };

    /// <summary>
    /// A description of the network on the far side of the VPN tunnel.
    /// This must match the expectations of the other side, or the connection will fail.
    /// </summary>
    public static TrafficSelectorSetting RemoteTrafficSelector { get; set; } = new()
    {
        StartPort = 0,
        EndPort = 65535,
        StartAddress = "192.168.0.40",
        EndAddress = "192.168.0.40"
    };

    /// <summary>
    /// Declared IP address of this VPN node.
    /// It *MUST* match what is in ipsec.conf, otherwise auth will fail.
    /// <p></p>
    /// This is NOT the virtual addresses the web app will appear to be on --
    /// that is in <see cref="LocalTrafficSelector"/>
    /// <p></p>
    /// This does NOT need to be a real machine's address.
    /// </summary>
    //public static readonly string LocalIpAddress = "192.168.0.2"; // Hans
    public static string LocalIpAddress = "185.81.252.44"; // Behind NAT
    
    #endregion
    
    #region Web app proxying
    /// <summary>
    /// TCP port to use when client is using HTTP
    /// </summary>
    public static int WebAppHttpPort = 5223;
    
    /// <summary>
    /// TCP port to use when client is using HTTPS
    /// </summary>
    public static int WebAppHttpsPort = 7169;
    
    /// <summary>
    /// IPv4 address of the app we're tunnelling to. If on the same machine, use 127.0.0.1
    /// </summary>
    public static string WebAppIpAddress = "127.0.0.1";
    
    /// <summary>
    /// If supplied, this host name will be added to the headers of incoming requests.
    /// If blank or null, the incoming request headers will not be changed.
    /// <p></p>
    /// Use this if your WebApp is behind a reverse-proxy.
    /// <p></p>
    /// IMPORTANT: this will only work if calls are non-TLS <b>or</b>
    /// the target has certs in <see cref="TlsKeyPaths"/>
    /// </summary>
    public static string? WebAppHostName = "my-app.example.com";
    
    /// <summary>
    /// The SECRET api key for sending proxy messages.
    /// Callers should NOT send this directly, but use
    /// a time-coded version.
    /// </summary>
    public static string ApiKey = "replace-me";
    
    /// <summary>
    /// Target IP => Key paths (as <c>$"{privateKey};{fullCert}"</c>)
    /// <p></p>
    /// If an incoming TCP/IP stream has a TLS 'hello' message,
    /// AND the destination IP address matches one of the keys
    /// in this dictionary, then we will unwrap the TLS stream
    /// using the certificate, and pass along to the web app.
    /// <p></p>
    /// This allows us to give correct certificates to callers
    /// regardless of the final app.
    /// </summary>
    public static Dictionary<string,string>? TlsKeyPaths = new(){
        {"55.55.55.55","/root/vpnCerts/hans-privkey.pem;/root/vpnCerts/hans-fullchain.pem"}
    };
    
    #endregion
    
    #region Debug tools and logging
    /// <summary>
    /// Prefix on capture files
    /// </summary>
    public static string FileBase = Platform.Current() == Platform.Kind.Linux ? "/root/airlift/" : @"C:\temp\traffic\";
    
    /// <summary>
    /// Listener prefix for the web "airlift". This helps you pull logs.
    /// </summary>
    //public static string HttpPrefix = "://+:8011/"; // <-- this will require root/admin access.
    public static string HttpPrefix = "://localhost:8011/"; // <-- use this if testing locally
    
    /// <summary>
    /// INSECURE if true
    /// <p></p>
    /// If true, VirtualVPN will listen for HTTP connections
    /// NOT on an IPSEC tunnel, and will allow access to the
    /// network capture files.  This is only for development
    /// and diagnostics and should normally be 'false'.
    /// </summary>
    public static bool RunAirliftSite = false;
    
    /// <summary>
    /// If true, traffic will be captured into files.
    /// The number of files captured depends on log level.
    /// </summary>
    public static bool CaptureTraffic = false;
    
    /// <summary>
    /// Log level that will be set at startup
    /// </summary>
    public static LogLevel DefaultLogLevel = LogLevel.Info;
    
    /// <summary>
    /// Log packet traffic at the TCP stack level.
    /// This is useful for diagnosing badly behaved
    /// firewalls and proxies.
    /// </summary>
    public static bool DoTcpTrafficLogs = false;
    
    /// <summary>
    /// If true, the output of `Bit.Describe` generates C# code.
    /// Otherwise it looks like StrongSwan log format.
    /// </summary>
    public static bool CodeModeForDescription = false;
    #endregion
    
    #region Timings and tuning parameters
    /// <summary>
    /// Median time to pause between event pump runs.
    /// If connections are active, the event pump will run faster.
    /// If no connections are up, the event pump will run slower.
    /// </summary>
    public static TimeSpan EventPumpRate { get; set; } = TimeSpan.FromSeconds(0.5);
    
    /// <summary>
    /// How long should a socket connection be attempted before failing
    /// </summary>
    public static TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How long a TCP session is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan TcpTimeout { get; set; } = TimeSpan.FromSeconds(30);
    
    /// <summary>
    /// How long an *established* ESP session is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan EspTimeout { get; set; } = TimeSpan.FromSeconds(300);
    
    /// <summary>
    /// How long an IKE session under negotiation is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan IkeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How often keep-alive messages are sent for ChildSa connections we started
    /// </summary>
    public static TimeSpan KeepAliveTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How often to print statistics to the console.
    /// Stats are written with 'Info' log level.
    /// </summary>
    public static TimeSpan StatsFrequency { get; set; } = TimeSpan.FromSeconds(30);

    #endregion

    #region Cryptographic parameters
    /// <summary>
    /// Integrity algorithm ID.
    /// Supplied to peer when VirtualVPN is initiator
    /// </summary>
    //public static readonly uint StartIntegrity = (uint)IntegId.AUTH_HMAC_SHA2_256_128; // preferred
    public static uint StartIntegrity = (uint)IntegId.AUTH_HMAC_SHA1_96; // accepted by old systems
    
    /// <summary>
    /// Pseudo-random function algorithm ID.
    /// Supplied to peer when VirtualVPN is initiator
    /// </summary>
    //public static uint StartRandomFunction = (uint)PrfId.PRF_HMAC_SHA2_256; // preferred
    public static uint StartRandomFunction = (uint)PrfId.PRF_HMAC_SHA1; // accepted by old systems
    
    /// <summary>
    /// Key exchange algorithm ID.
    /// Supplied to peer when VirtualVPN is initiator
    /// </summary>
    public static uint StartKeyExchangeFunction = (uint)DhId.DH_14;
    #endregion
}