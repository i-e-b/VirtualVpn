using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using VirtualVpn.TcpProtocol;

namespace VirtualVpn.TlsWrappers;

public class TlsAdaptorForRealSocket : ISocketAdaptor
{
    private bool _faulted, _closed;
    private readonly SocketStream _streamWrapper;
    private readonly SslStream _sslWrapper;

    public TlsAdaptorForRealSocket(Socket socket, string host)
    {
        Connected = false;
        _faulted = false;
        _closed = false;
        _streamWrapper = new SocketStream(socket);
        _sslWrapper = new SslStream(_streamWrapper, false, AnyCertificate);
        
        Log.Debug($"Starting TlsAdaptorForRealSocket. Socket connected={socket.Connected}. Calling for authentication");
        
        ThreadPool.QueueUserWorkItem(hostStr =>
        {
            _sslWrapper.AuthenticateAsClient(hostStr);
            Log.Debug($"TlsAdaptorForRealSocket. Authentication complete. Success={_sslWrapper.IsAuthenticated}");
            Connected = true;
        }, host, true);
    }

    /// <summary>
    /// Accept any server certificate
    /// </summary>
    private static bool AnyCertificate(object a, X509Certificate? b, X509Chain? c, SslPolicyErrors d) => true;

    public void Dispose()
    {
        _closed = true;
        
        _sslWrapper.Dispose();
        _streamWrapper.Socket?.Dispose();
    }

    public void Close()
    {
        if (_closed) return;
        _closed = true;
        
        _sslWrapper.Close();
        _streamWrapper.Socket?.Close();
    }

    public bool Connected { get; private set; }
    public int Available => _streamWrapper.Socket?.Available ?? 0;
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        if (_closed)
        {
            Log.Warn("TlsAdaptorForRealSocket.IncomingFromTunnel: use after closed");
            return 0;
        }

        try
        {
            _sslWrapper.Write(buffer, offset, length);
            return length;
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
        if (_closed)
        {
            Log.Warn("TlsAdaptorForRealSocket.OutgoingFromLocal: use after closed");
            return 0;
        }
        
        try
        {
            return _sslWrapper.Read(buffer);
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