using VirtualVpn.Enums;
using VirtualVpn.EspProtocol.Payloads.PayloadSubunits;
using VirtualVpn.Helpers;
// ReSharper disable FieldCanBeMadeReadOnly.Global
#pragma warning disable CA2211 // constants should not be public

namespace VirtualVpn;

public static class Settings
{
    /// <summary>
    /// Prefix on capture files
    /// </summary>
    public static string FileBase = Platform.Current() == Platform.Kind.Linux ? "/root/airlift/" : @"C:\temp\traffic\";
    
    /// <summary>
    /// Listener prefix for the web "airlift". This helps you pull logs.
    /// </summary>
    public const string HttpPrefix = "://+:8011/"; // <-- this will require root/admin access.
    //public const string HttpPrefix = "://localhost:8011/"; // <-- use this if testing locally
    
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
    /// PSK for session establishment
    /// </summary>
    public static string PreSharedKeyString = "ThisIsForTestOnlyDontUse";
    
    /// <summary>
    /// If true, traffic will be captured into files
    /// </summary>
    public static bool CaptureTraffic = false;
    
    /// <summary>
    /// Log level that will be set at startup
    /// </summary>
    public const LogLevel DefaultLogLevel = LogLevel.Info;
    
    /// <summary>
    /// If true, the output of `Bit.Describe` generates C# code.
    /// Otherwise it looks like StrongSwan log format.
    /// </summary>
    public static bool CodeModeForDescription = false;
    
    /// <summary>
    /// Median time to pause between event pump runs.
    /// If connections are active, the event pump will run faster.
    /// If no connections are up, the event pump will run slower.
    /// </summary>
    public static TimeSpan EventPumpRate => TimeSpan.FromSeconds(0.5);

    /// <summary>
    /// How long a TCP session is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan TcpTimeout => TimeSpan.FromSeconds(60);
    
    /// <summary>
    /// How long an *established* ESP session is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan EspTimeout => TimeSpan.FromSeconds(300);
    
    /// <summary>
    /// How long an IKE session under negotiation is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan IkeTimeout => TimeSpan.FromSeconds(30);

    /// <summary>
    /// How often keep-alive messages are sent for ChildSa connections we started
    /// </summary>
    public static TimeSpan KeepAliveTimeout => TimeSpan.FromSeconds(10);
    
    /// <summary>
    /// A description of the network on our side of the VPN tunnel.
    /// This must match the expectations of the other side, or the connection will fail.
    /// </summary>
    public static TrafficSelector LocalTrafficSelector => new() {
        Type = TrafficSelectType.TS_IPV4_ADDR_RANGE,
        Protocol = IpProtocol.ANY,
        StartPort = 0,
        EndPort = 65535,
        StartAddress = new byte[] { 55, 55, 0, 0 },
        EndAddress = new byte[] { 55, 55, 255, 255 }
    };

    /// <summary>
    /// A description of the network on the far side of the VPN tunnel.
    /// This must match the expectations of the other side, or the connection will fail.
    /// </summary>
    public static TrafficSelector RemoteTrafficSelector => new() {
        Type = TrafficSelectType.TS_IPV4_ADDR_RANGE,
        Protocol = IpProtocol.ANY,
        StartPort = 0,
        EndPort = 65535,
        StartAddress = new byte[] { 192,168,0,40 },
        EndAddress = new byte[] { 192,168,0,40 }
    };

    /// <summary>
    /// Declared IP address of this VPN node.
    /// It must match what is in ipsec.conf, otherwise auth will fail.
    /// <p></p>
    /// This does NOT need to be a real machine's address.
    /// </summary>
    public static readonly byte[] LocalIpAddress = { 192, 168, 0, 2 }; // Hans
    //public static readonly byte[] LocalIpAddress = { 185, 81, 252, 44 }; // Behind NAT
    
    /// <summary>
    /// TCP port of the app we're tunnelling
    /// </summary>
    public const int WebAppPort = 5223;
    
    /// <summary>
    /// IPv4 address of the app we're tunnelling. If on the same machine, use 127.0.0.1
    /// </summary>
    public static readonly byte[] WebAppIpAddress = { 127, 0, 0, 1 };
}