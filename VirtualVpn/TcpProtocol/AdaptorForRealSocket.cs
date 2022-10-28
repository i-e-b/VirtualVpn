using System.Net.Sockets;
using VirtualVpn.Logging;
using VirtualVpn.Web;

namespace VirtualVpn.TcpProtocol;

internal class AdaptorForRealSocket : ISocketAdaptor
{
    private readonly Socket _socket;
    private readonly HttpHostHeaderRewriter _reWriter;
    private bool _faulted, _disposed;

    /// <summary>
    /// Wrap an OS socket connection as an ISocketAdaptor
    /// </summary>
    /// <param name="socket">Underlying connection</param>
    /// <param name="webAppHostName">The website host, as in the 'Host:' HTTP header</param>
    public AdaptorForRealSocket(Socket socket, string webAppHostName)
    {
        _faulted = false;
        _disposed = false;
        _socket = socket;
        _reWriter = new HttpHostHeaderRewriter(webAppHostName);
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
            var translatedBuffer = _reWriter.Process(buffer, ref offset, ref length);
            
            return _socket.Send(translatedBuffer, offset, length, SocketFlags.None);
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