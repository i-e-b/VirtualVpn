namespace VirtualVpn.TcpProtocol;

public static class TcpDefaults
{
    /// <summary>
    /// Default Maximum-Segment-Size.
    /// This conservative setting as per https://tools.ietf.org/html/rfc879
    /// </summary>
    public const UInt16 DefaultMss = 536;
    
    /// <summary>
    /// Maximum Segment Lifetime. Default is one minute
    /// </summary>
    public static readonly TimeSpan MaxSegmentLifetime = TimeSpan.FromSeconds(60);
    
    /// <summary>
    /// Initial connect timeout.
    /// This is doubled on each retry
    /// </summary>
    public static readonly TimeSpan InitialRto = TimeSpan.FromMilliseconds(500);
    
    /// <summary>
    /// Minimum retransmission timeout (RTO).
    /// https://tools.ietf.org/html/rfc6298#page-3
    /// </summary><remarks>
    /// RFC 6298 (2.4) says: 'Whenever RTO is computed, if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second'
    /// Linux uses a minimum RTO of 200 ms
    /// </remarks>
    public static readonly TimeSpan MinimumRto = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Number of times we will retry a SYN before timing out
    /// </summary>
    public const int BackoffLimit = 6;
}