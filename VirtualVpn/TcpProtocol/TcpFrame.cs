using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Container for a TCP segment plus its wrapping IPv4 headers
/// </summary>
public class TcpFrame
{
    public TcpSegment Tcp { get; set; }
    public IpV4Packet Ip { get; set; }

    public TcpFrame(TcpSegment tcp, IpV4Packet ip)
    {
        Tcp = tcp; Ip = ip;
    }
}