using System.Net.Sockets;

namespace VirtualVpn.TcpProtocol;

public interface ISocketAdaptor:IDisposable
{
    /// <summary>
    /// Close the adaptor and its source
    /// </summary>
    void Close();
    
    /// <summary>
    /// True if the adaptor is connected to its source
    /// </summary>
    bool Connected { get; }
    
    /// <summary>
    /// How much data does the local side have ready
    /// to send through the tunnel?
    /// </summary>
    int Available { get; }
    
    /// <summary>
    /// Data incoming from the tunnel, to write to local side
    /// </summary>
    int IncomingFromTunnel(byte[] buffer, int offset, int length);
    
    /// <summary>
    /// Read data from local side to send through the tunnel
    /// </summary>
    int OutgoingFromLocal(byte[] buffer);
}