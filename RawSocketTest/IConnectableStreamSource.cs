namespace RawSocketTest;

/// <summary>
/// Factory methods for connecting a stream to a URI by sockets
/// </summary>
public interface IConnectableStreamSource
{
    /// <summary>
    /// Connect to an unsecured target URI.
    /// </summary>
    /// <param name="connectionTarget">Uri of target service</param>
    /// <param name="connectionTimeout">Timeout for connection and data transfer</param>
    /// <returns>Readable and writable stream connected to target by an open socket</returns>
    Stream ConnectUnsecured(Uri connectionTarget, TimeSpan connectionTimeout);

    /// <summary>
    /// Connect to an target URI over an SSL connection.
    /// This method does not attempt to verify certificate trust.
    /// Use only with trusted resources.
    /// </summary>
    /// <param name="connectionTarget">Uri of target service</param>
    /// <param name="connectionTimeout">Timeout for connection and data transfer</param>
    /// <returns>Readable and writable stream connected to target by an open socket</returns>
    Stream ConnectSSL(Uri connectionTarget, TimeSpan connectionTimeout);
}