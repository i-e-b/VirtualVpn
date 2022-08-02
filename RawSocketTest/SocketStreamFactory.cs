using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace RawSocketTest;

/// <summary>
/// Factory methods for connecting a stream to a URI by sockets
/// </summary>
public class SocketStreamFactory : IConnectableStreamSource
{
    /// <summary>
    /// Connect to an unsecured target URI.
    /// </summary>
    /// <param name="connectionTarget">Uri of target service</param>
    /// <param name="connectionTimeout">Timeout for connection and data transfer</param>
    /// <returns>Readable and writable stream connected to target by an open socket</returns>
    public Stream ConnectUnsecured(Uri connectionTarget, TimeSpan connectionTimeout)
    {
        var s = new SocketStream(
            new System.Net.Sockets.Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { Blocking = true }
        );

        if (s.Socket == null) throw new Exception("Failed to connect to socket stream");

        s.Socket.SendTimeout = s.Socket.ReceiveTimeout = (int)connectionTimeout.TotalMilliseconds;
        s.Socket.Connect(connectionTarget.Host, connectionTarget.Port);
        return s;
    }

    /// <summary>
    /// Dummy certification validation callback.
    /// Always accepts certificates.
    /// </summary>
    public bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        return true;
    }


    /// <summary>
    /// Connect to an target URI over an SSL connection.
    /// This method does not attempt to verify certificate trust.
    /// Use only with trusted resources.
    /// </summary>
    /// <param name="connectionTarget">Uri of target service</param>
    /// <param name="connectionTimeout">Timeout for connection and data transfer</param>
    /// <returns>Readable and writable stream connected to target by an open socket</returns>
    public Stream ConnectSSL(Uri connectionTarget, TimeSpan connectionTimeout)
    {
        var stream = new SslStream(ConnectUnsecured(connectionTarget, connectionTimeout),
            false,
            RemoteCertificateValidationCallback);
        stream.AuthenticateAsClient(connectionTarget.Host);
        return stream;
    }
}