using System.Net;
using System.Net.Sockets;

namespace RawSocketTest;

public class UdpServer : IDisposable
{
    private readonly Action<byte[], IPEndPoint>? _ikeResponder;
    private readonly Action<byte[], IPEndPoint>? _speResponder;
    private readonly Thread _commsThreadIke;
    private readonly Thread _commsThreadSpe;
    private volatile bool _running;
    private readonly UdpClient _speClient;
    private readonly UdpClient _ikeClient;

    public UdpServer(Action<byte[], IPEndPoint>? ikeResponder, Action<byte[], IPEndPoint>? speResponder)
    {
        _ikeResponder = ikeResponder;
        _speResponder = speResponder;
        
        var speEndpoint = new IPEndPoint(IPAddress.Any, 4500);
        _speClient = new UdpClient(speEndpoint);
        
        var ikeEndpoint = new IPEndPoint(IPAddress.Any, 500);
        _ikeClient = new UdpClient(ikeEndpoint);
        
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
        var sender = new IPEndPoint(IPAddress.Any, 0);
        while (_running)
        {
            Console.WriteLine("Listening on 500...");
            var buffer = _ikeClient.Receive(ref sender);
            Console.WriteLine($"ListenPort=500 EphemeralPort={sender.Port} Caller={sender.Address} Data->{buffer.Length} bytes");
            _ikeResponder?.Invoke(buffer, sender);
        }
    }
    
    private void SpeLoop()
    {
        var sender = new IPEndPoint(IPAddress.Any, 0);
        while (_running)
        {
            Console.WriteLine("Listening on 4500...");
            var buffer = _speClient.Receive(ref sender);
            Console.WriteLine($"ListenPort=4500 EphemeralPort={sender.Port} Caller={sender.Address} Data->{buffer.Length} bytes");
            _speResponder?.Invoke(buffer, sender);
        }
    }

    public void SendIke(byte[] data, IPEndPoint target, out int bytesSent)
    {
        bytesSent = _ikeClient.Send(data, data.Length, target);
        // this seems to cause 500 port to be used on the way back too
        // unlike `Socket.SendTo(buf,flags,target)` which gives an ephemeral port
    }

    public void Dispose()
    {
        _running = false;
        _speClient.Dispose();
        _ikeClient.Dispose();
        GC.SuppressFinalize(this);
    }
}