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
    private readonly Socket _inSock;
    private byte[] _buffer;

    public UdpServer()
    {
        _outSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { Blocking = true };

        _buffer = new byte[1048576];
        _inSock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { Blocking = true };
        
        _inSock.Bind(new IPEndPoint(IPAddress.Any, 500));
        //_inSock.Listen();
        
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
        while (_running)
        {
            Console.WriteLine("Listening on 500...");
            var actual = _inSock.Receive(_buffer);
            Console.WriteLine($"Got message, {actual} bytes.");
        }

        /*var localEp = new IPEndPoint(IPAddress.Any, 500);
        using var client = new UdpClient(localEp);

        Console.WriteLine("Waiting for a client...");

        var sender = new IPEndPoint(IPAddress.Any, 0);

        while(_running)
        {
            Console.WriteLine("Waiting (500)");
            var buffer = client.Receive(ref sender);

            Console.WriteLine($"Port={sender.Port}  Caller={sender.Address} Data={Encoding.UTF8.GetString(buffer, 0, buffer.Length)}");
        }*/
    }
    
    private void SpeLoop()
    {
        var localEp = new IPEndPoint(IPAddress.Any, 4500);
        using var client = new UdpClient(localEp);

        Console.WriteLine("Waiting for a client...");

        var sender = new IPEndPoint(IPAddress.Any, 0);

        while(_running)
        {
            Console.WriteLine("Waiting (4500)");
            var buffer = client.Receive(ref sender);

            Console.WriteLine($"Port={sender.Port}  Caller={sender.Address} Data={Encoding.UTF8.GetString(buffer, 0, buffer.Length)}");
        }
    }

    public int SendTo(byte[] buf, SocketFlags flags, IPEndPoint target) => _outSock.SendTo(buf,flags,target);

    public void Dispose()
    {
        _running = false;
        _outSock.Dispose();
        GC.SuppressFinalize(this);
    }
}