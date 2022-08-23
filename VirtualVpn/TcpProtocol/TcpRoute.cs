using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TcpProtocol;

public class TcpRoute
{
    public int LocalPort { get; set; }
    public int RemotePort { get; set; }
    public IpV4Address LocalAddress { get; set; } = IpV4Address.Any;
    public IpV4Address RemoteAddress { get; set; } = IpV4Address.Any;
}