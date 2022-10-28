using System.Diagnostics.CodeAnalysis;

namespace VirtualVpn.Logging;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum LogLevel
{
    None = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Debug = 4,
    
    /// <summary>
    /// Include very verbose messages
    /// </summary>
    Trace = 5,
    
    /// <summary>
    /// Include raw data for debugging crypto
    /// </summary>
    Crypto = 100,
    
    /// <summary>
    /// Output all logs
    /// </summary>
    Everything = 255
}