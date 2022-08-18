namespace RawSocketTest;

public static class Settings
{
    /// <summary>
    /// Prefix on capture files
    /// </summary>
    public const string FileBase = "/root/airlift/";
    //public const string FileBase = @"C:\temp\zzz";

    /// <summary>
    /// Declared IP address of this VPN node.
    /// It must match what is in ipsec.conf, otherwise auth will fail.
    /// </summary>
    public static readonly byte[] LocalIpAddress = { 192, 168, 0, 2 }; // Hans
    //public static readonly byte[] LocalIpAddress = { 185, 81, 252, 44 }; // Behind NAT
    
    /// <summary>
    /// If true, traffic will be captured into files
    /// </summary>
    public static bool CaptureTraffic = true;
    
    /// <summary>
    /// Log level that will be set at startup
    /// </summary>
    public const LogLevel DefaultLogLevel = LogLevel.Info;
    
    /// <summary>
    /// If true, the output of `Bit.Describe` generates C# code.
    /// Otherwise it looks like StrongSwan log format.
    /// </summary>
    public static bool CodeModeForDescription = true;
    
    /// <summary>
    /// Listener prefix for the web "airlift". This helps you pull logs.
    /// </summary>
    public const string HttpPrefix = "://+:8011/"; // <-- this will require root/admin access.
    //public const string HttpPrefix = "://localhost:8011/"; // <-- use this if testing locally
    
    /// <summary>
    /// How long to pause between event pump runs.
    /// </summary>
    public static TimeSpan EventPumpRate => TimeSpan.FromSeconds(5);

    /// <summary>
    /// How long a TCP session is allowed to go without any traffic before being closed.
    /// </summary>
    public static TimeSpan TcpTimeout => TimeSpan.FromSeconds(30);
}