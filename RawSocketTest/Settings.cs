namespace RawSocketTest;

public static class Settings
{
    /// <summary>
    /// Prefix on capture files
    /// </summary>
    public const string FileBase = ".";
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
    public const bool CaptureTraffic = true;
    
    /// <summary>
    /// Log level that will be set at startup
    /// </summary>
    public const LogLevel DefaultLogLevel = LogLevel.Info;
    
    /// <summary>
    /// If true, the output of `Bit.Describe` generates C# code.
    /// Otherwise it looks like StrongSwan log format.
    /// </summary>
    public const bool CodeModeForDescription = true;
}