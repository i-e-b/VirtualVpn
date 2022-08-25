namespace VirtualVpn.TcpProtocol;

public interface ITcpAdaptor
{
    void Close();
    void Reply(TcpSegment seg, TcpRoute route);
}