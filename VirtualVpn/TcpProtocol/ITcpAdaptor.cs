namespace VirtualVpn.TcpProtocol;

public interface ITcpAdaptor
{
    /// <summary>
    /// The socket is closed. Adaptor should stop event pump
    /// and no longer route any packets to the socket.
    /// </summary>
    void Close();
    
    /// <summary>
    /// The socket is closing.
    /// Adaptor should pump events while the session end handshake happens
    /// </summary>
    void Closing();
    
    /// <summary>
    /// Send data through the tunnel
    /// </summary>
    void Reply(TcpSegment seg, TcpRoute route);
}