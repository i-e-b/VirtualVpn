using System.Net;
using System.Net.Sockets;

namespace VirtualVpn.Helpers;


public interface IUdpServer
{
    /// <summary>
    /// Send bytes to a target, matching the target port if 500 or 4500
    /// </summary>
    void SendRaw(byte[] message, IPEndPoint to);
}

public class UdpServer : IUdpServer, IDisposable
{
    private readonly Action<byte[], IPEndPoint>? _ikeResponder;
    private readonly Action<byte[], IPEndPoint>? _speResponder;
    private readonly Thread _commsThreadIke;
    private readonly Thread _commsThreadSpe;
    private volatile bool _running;
    private readonly UdpClient _speClient;
    private readonly UdpClient _ikeClient;

    /// <summary> Total bytes received </summary>
    public ulong TotalIn { get; private set; }
    /// <summary> Total bytes sent </summary>
    public ulong TotalOut { get; private set; }

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
        
        TotalIn = 0;
        TotalOut = 0;
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
            try
            {
                Log.Info("Listening on 500...");
                var buffer = _ikeClient.Receive(ref sender);
                TotalIn += (ulong)buffer.Length;
                _ikeResponder?.Invoke(buffer, sender);
            }
            catch (Exception ex)
            {
                Log.Error("Failure in IKE loop", ex);
            }
        }
    }
    
    private void SpeLoop()
    {
        var sender = new IPEndPoint(IPAddress.Any, 0);
        while (_running)
        {
            try
            {
                Log.Info("Listening on 4500...");
                var buffer = _speClient.Receive(ref sender);
                TotalIn += (ulong)buffer.Length;
                _speResponder?.Invoke(buffer, sender);
            }
            catch (Exception ex)
            {
                Log.Error("Failure in SPE/ESP loop", ex);
            }
        }
    }

    /// <summary>
    /// Send bytes to a target, matching the target port if 500 or 4500
    /// </summary>
    public void SendRaw(byte[] data, IPEndPoint target)
    {
        // `UdpClient.Send()` seems to cause 500 port to be used on the way back,
        // unlike `Socket.SendTo(buf,flags,target)` which gives an ephemeral port

        TotalOut += (ulong)data.Length;
        switch (target.Port)
        {
            case 4500:
            {
                var addr = _speClient.Client.LocalEndPoint as IPEndPoint;
                Log.Debug($"    Sending from {addr?.Address}[{addr?.Port}] to {target.Address}[{target.Port}] ({data.Length} bytes)");
                _speClient.Send(data, data.Length, target);
                break;
            }
            case 500:
            {
                var addr = _ikeClient.Client.LocalEndPoint as IPEndPoint;
                Log.Debug($"    Sending from {addr?.Address}[{addr?.Port}] to {target.Address}[{target.Port}] ({data.Length} bytes)");
                _ikeClient.Send(data, data.Length, target);
                break;
            }
            default:
                Log.Warn($"WARNING: target port of {target.Port} is not recognised! Will send from source port of 500");
                _ikeClient.Send(data, data.Length, target);
                break;
        }
    }

    public void Dispose()
    {
        _running = false;
        _speClient.Dispose();
        _ikeClient.Dispose();
        GC.SuppressFinalize(this);
    }
}