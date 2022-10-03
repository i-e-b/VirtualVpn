using System.Net.Sockets;

namespace VirtualVpn.TcpProtocol;

internal class AdaptorForRealSocket : ISocketAdaptor
{
    private readonly Socket _socket;
    private bool _faulted, _disposed;

    public AdaptorForRealSocket(Socket socket)
    {
        _faulted = false;
        _disposed = false;
        _socket = socket;
    }
    
    ~AdaptorForRealSocket()
    {
        if (_disposed) return;
        Log.Warn("AdaptorForRealSocket hit destructor without being disposed");
        _socket.Dispose();
    }

    public void Dispose() => Close();

    public void Close() {
        if (_disposed) return;
        _disposed = true;
        _socket.Dispose();
    }

    public bool Connected => _socket.Connected;
    public int Available => _socket.Available;
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        try
        {
            return _socket.Send(buffer, offset, length, SocketFlags.None);
        }
        catch (Exception ex)
        {
            Log.Error("Writing to socket failed", ex);
            _faulted = true;
            return 0;
        }
    }

    public int OutgoingFromLocal(byte[] buffer)
    {
        try
        {
            return _socket.Receive(buffer);
        }
        catch (Exception ex)
        {
            Log.Error("Reading from socket failed", ex);
            _faulted = true;
            return 0;
        }
    }

    public bool IsFaulted()
    {
        return _faulted;
    }
}