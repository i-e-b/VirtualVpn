using System.Net;
using System.Net.Sockets;
using System.Text;

namespace RawSocketTest;

public class UdpServer : IDisposable
{
    private readonly Thread _commsThreadIke;
    private readonly Thread _commsThreadSpe;
    private readonly Socket _outSock;
    private volatile bool _running;

    public UdpServer()
    {
        _outSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { Blocking = true };
        _commsThreadIke = new Thread(IkeLoop){IsBackground = true};
        _commsThreadSpe = new Thread(SpeLoop){IsBackground = true};
    }

    public void Start()
    {
        _running = true;
        _commsThreadIke.Start();
        _commsThreadSpe.Start();
    }

    private void IkeLoop()
    {
        var buffer = new byte[1024];
        var ipep = new IPEndPoint(IPAddress.Any, 500);
        using var newsock = new UdpClient(ipep);

        Console.WriteLine("Waiting for a client...");

        var sender = new IPEndPoint(IPAddress.Any, 0);

        while(_running)
        {
            buffer = newsock.Receive(ref sender);

            Console.WriteLine($"Port={sender.Port}  Caller={sender.Address} Data={Encoding.UTF8.GetString(buffer, 0, buffer.Length)}");
        }
    }
    
    private void SpeLoop()
    {
        var buffer = new byte[1024];
        var ipep = new IPEndPoint(IPAddress.Any, 4500);
        using var newsock = new UdpClient(ipep);

        Console.WriteLine("Waiting for a client...");

        var sender = new IPEndPoint(IPAddress.Any, 0);

        while(_running)
        {
            buffer = newsock.Receive(ref sender);

            Console.WriteLine($"Port={sender.Port}  Caller={sender.Address} Data={Encoding.UTF8.GetString(buffer, 0, buffer.Length)}");
        }
    }

    public int SendTo(byte[] buf, SocketFlags flags, EndPoint target) => _outSock.SendTo(buf,flags,target);

    public void Dispose()
    {
        _running = false;
        _outSock.Dispose();
    }
}