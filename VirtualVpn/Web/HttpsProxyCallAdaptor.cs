using VirtualVpn.TcpProtocol;

namespace VirtualVpn.Web;

/// <summary>
/// Pretend that an API proxy call is a HTTP over TLS over TCP socket client
/// This class does secured calls. For unsecured, see <see cref="HttpProxyCallAdaptor"/>.
/// </summary>
public class HttpsProxyCallAdaptor : ISocketAdaptor
{
    public HttpsProxyCallAdaptor(HttpProxyRequest request, HttpProxyResponse response)
    {
        // IEB: continue from here
        // TODO: get an `SslStream` wrapped around a stream adaptor for the request/response.
        // ALSO: generalise the HTTP document & chunked detection from `HttpProxyCallAdaptor`
        //       into that stream adaptor.
    }

    public void Dispose()
    {
        throw new NotImplementedException();
    }

    public void Close()
    {
        throw new NotImplementedException();
    }

    public bool Connected { get; }
    public int Available { get; }
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        throw new NotImplementedException();
    }

    public int OutgoingFromLocal(byte[] buffer)
    {
        throw new NotImplementedException();
    }
}