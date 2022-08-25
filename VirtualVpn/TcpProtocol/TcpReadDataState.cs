namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Overall state of data reception
/// </summary>
public enum TcpReadDataState
{
    /// <summary>
    /// No data yet received
    /// </summary>
    Waiting = 0,
    
    /// <summary>
    /// Some data has been received. Sender has not requested a flush
    /// </summary>
    Cached = 1,
    
    /// <summary>
    /// Data has been received, and sender has requested
    /// that it be forwarded.
    /// </summary>
    FlushRequest = 2,
    
    /// <summary>
    /// Sender has sent a finalisation message.
    /// All data should be complete.
    /// </summary>
    Finalised = 4
}