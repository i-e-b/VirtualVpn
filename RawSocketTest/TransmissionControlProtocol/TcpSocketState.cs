using System.Diagnostics.CodeAnalysis;

namespace RawSocketTest.TransmissionControlProtocol;

/// <summary>
/// States for an individual TCP session
/// </summary>
[SuppressMessage("ReSharper", "UnusedMember.Global")]
public enum TcpSocketState
{
    /// <summary> No connection state at all </summary>
    Closed = 0,

    /// <summary> (Server) Waiting for a connection request from any remote TCP end-point. </summary>
    Listen,

    /// <summary> (Client) Waiting for a matching connection request after having sent a connection request. </summary>
    SynSent,

    /// <summary> (Server) Waiting for a confirming connection request acknowledgment after having both received and sent a connection request. </summary>
    SynReceived,

    /// <summary> An open connection, data received can be delivered to the user. The normal state for the data transfer phase of the connection. </summary>
    Established,

    /// <summary> Waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent. </summary>
    FinWait1,

    /// <summary> Waiting for a connection termination request from the remote TCP. </summary>
    FinWait2,

    /// <summary> Waiting for a connection termination request from the local user. </summary>
    CloseWait,

    /// <summary> Waiting for a connection termination request acknowledgment from the remote TCP. </summary>
    Closing,

    /// <summary> Waiting for an acknowledgment of the connection termination request previously sent to the remote TCP
    /// (which includes an acknowledgment of its connection termination request). </summary>
    LastAck,

    /// <summary> Waiting for enough time to pass to be sure that all remaining packets on the connection have expired. </summary>
    TimeWait,
}