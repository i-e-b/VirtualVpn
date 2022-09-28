using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using VirtualVpn.TcpProtocol;

namespace VirtualVpn.TlsWrappers;

public class TlsAdaptorForRealSocket : ISocketAdaptor
{
    private bool _faulted;
    private readonly SocketStream _streamWrapper;
    private readonly SslStream _sslWrapper;

    public TlsAdaptorForRealSocket(Socket socket, string host)
    {
        _faulted = false;
        _streamWrapper = new SocketStream(socket);
        _sslWrapper = new SslStream(_streamWrapper, false, AnyCertificate);
        
        Log.Debug($"Starting TlsAdaptorForRealSocket. Socket connected={socket.Connected}. Calling for authentication");
        
        _sslWrapper.AuthenticateAsClient(host);
        Log.Debug($"TlsAdaptorForRealSocket. Authentication complete. Success={_sslWrapper.IsAuthenticated}");
    }

    /// <summary>
    /// Accept any server certificate
    /// </summary>
    private static bool AnyCertificate(object a, X509Certificate? b, X509Chain? c, SslPolicyErrors d) => true;

    public void Dispose()
    {
        _sslWrapper.Dispose();
        _streamWrapper.Socket?.Dispose();
    }

    public void Close()
    {
        _sslWrapper.Close();
        _streamWrapper.Socket?.Close();
    }

    public bool Connected => _streamWrapper.Socket?.Connected ?? false;
    public int Available => _streamWrapper.Socket?.Available ?? 0;
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
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