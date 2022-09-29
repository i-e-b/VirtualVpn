using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using VirtualVpn.Helpers;
using VirtualVpn.TcpProtocol;

namespace VirtualVpn.TlsWrappers;

/// <summary>
/// Wrap a socket connected to a TLS session,
/// unpack it with a set a certificates (this
/// class acting as the 'server').
/// Then expose the underlying plain stream
/// <p></p>
/// This class is the server version of <see cref="TlsHttpProxyCallAdaptor"/>.
/// This class is agnostic of the underlying protocol.
/// <p></p>
/// The ISocketAdaptor interface is driver by <see cref="TcpAdaptor"/> as it it were the
/// WebApp. We terminate that, act as the TlsServer, and pump decoded messages to the
/// real socket that we own privately.
/// </summary>
public class TlsUnwrap : ISocketAdaptor
{
    private readonly SslServerAuthenticationOptions _authOptions;
    private readonly SslStream _sslStream;
    
    private X509Certificate? _certificate;
    private ISocketAdaptor? _socket;
    private volatile bool _running, _faulted;
    
    private readonly BlockingBidirectionalBuffer _tunnelSideBuffer;
    private readonly Thread _pumpThreadIncoming;
    private readonly Thread _pumpThreadOutgoing;

    /// <summary>
    /// Try to create a TLS re-wrapper, given paths to certificates and a connection.
    /// If the certificates can't be loaded, the connection function will not be called,
    /// and an exception will be thrown.
    /// <p></p>
    /// Due to unresolved bugs in that operating system, this will probably not work on Windows.
    /// </summary>
    /// <param name="tlsKeyPaths">Paths to PEM keys, private first then public. separated by ';'. e.g. "/var/certs/privkey.pem;/var/certs/fullchain.pem"</param>
    /// <param name="outgoingConnectionFunction">
    /// Function that will start the OUTGOING socket, NOT the incoming client call
    /// The socket should connect with a TLS tunnel.
    /// </param>
    public TlsUnwrap(string tlsKeyPaths, Func<ISocketAdaptor> outgoingConnectionFunction)
    {
        if (string.IsNullOrWhiteSpace(tlsKeyPaths)) throw new Exception("Must have valid paths to PEM files to start TLS re-wrap");
        
        var filePaths = tlsKeyPaths.Split(';');
        if (filePaths.Length != 2) throw new Exception("TLS key paths must have exactly two files specified, separated by ';'");
        
        var privatePath = filePaths[0];
        var publicPath = filePaths[1];
        
        if (!File.Exists(privatePath)) throw new Exception($"Private key is not present, or this service does not have permissions to access it ({privatePath})");
        if (!File.Exists(publicPath)) throw new Exception($"Private key is not present, or this service does not have permissions to access it ({publicPath})");
        
        var enabledProtocols = (Platform.Current() == Platform.Kind.Windows)
            ? SslProtocols.Tls11 | SslProtocols.Tls12 // DO NOT use 1.3 on Windows: https://github.com/dotnet/runtime/issues/1720
            : SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13;

        _authOptions = new SslServerAuthenticationOptions
        {
            AllowRenegotiation = true,
            ClientCertificateRequired = false,
            EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            ServerCertificateSelectionCallback = CertSelect,
            EnabledSslProtocols = enabledProtocols,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };

        var startupThread = new Thread(() =>
        {
            Log.Debug("TlsUnwrap: Reading certificate");
            _certificate = GetX509Certificate(privatePath, publicPath);
            Log.Debug("TlsUnwrap: Starting socket connection");
            _socket = outgoingConnectionFunction();
            Log.Debug($"TlsUnwrap: Connection complete. Connected={_socket.Connected}");
        }) { IsBackground = true };
        startupThread.Start();
        
        _faulted = false;
        _running = true;
        
        Log.Debug("TlsUnwrap: Creating blocking buffer and SSL stream");
        _tunnelSideBuffer = new BlockingBidirectionalBuffer();
        _sslStream = new SslStream(_tunnelSideBuffer);

        _pumpThreadIncoming = new Thread(BufferPumpIncoming) { IsBackground = true };
        _pumpThreadIncoming.Start();
        
        _pumpThreadOutgoing = new Thread(BufferPumpOutgoing) { IsBackground = true };
        _pumpThreadOutgoing.Start();
    }

    private void BufferPumpIncoming()
    {
        var buffer = new byte[8192];

        while (_running && _socket?.Connected != true)
        {
            Log.Trace("TlsUnwrap: Waiting for connection");
            Thread.Sleep(50);
        }

        if (_socket is null)
        {
            Log.Critical("Lost socket in TlsUnwrap");
            _running = false;
            return;
        }

        // Pick up the client's hello, and start doing the hand-shake
        // The rest should happen as data is pumped around
        try
        {
            Log.Trace("TlsUnwrap: Starting SSL/TLS authentication");
            _sslStream.AuthenticateAsServer(_authOptions);
            Log.Debug("TlsUnwrap: SSL/TLS authenticated, starting incoming pump");
        }
        catch (Exception ex)
        {
            Log.Error("TlsUnwrap: Failure during AuthenticateAsServer", ex);
            _running = false;
            _faulted = true;
            return;
        }

        while (_running)
        {
            // Keep trying to move data around between the plain and encrypted buffers.
            // _socket <-> _plainSideBuffer | unwrap | _encryptionSideBuffer <-> ISocketAdaptor methods

            try
            {
                var read = _sslStream.Read(buffer, 0, buffer.Length);
                if (read > 0)
                {
                    _socket.IncomingFromTunnel(buffer, 0, read);
                    Log.Trace($"TlsUnwrap: Data from tunnel to web app: {read} bytes;\r\n{Bit.Describe("payload", buffer.Take(read))}");
                }
                else Log.Trace("TlsUnwrap: no data from tunnel");

                if (read < 1) Thread.Sleep(1);
            }
            catch (Exception ex)
            {
                Log.Debug($"Failure in TlsUnwrap.BufferPumpIncoming. Probably shutdown related: {ex.Message}");
                Thread.Sleep(50);
            }
        }
    }
    
    private void BufferPumpOutgoing()
    {
        var buffer = new byte[8192];

        Log.Trace("TlsUnwrap: Waiting for SSL/TLS authentication");
        // wait for SSL/TLS to come up
        while (_running && !_sslStream.IsAuthenticated)
        {
            Thread.Sleep(50);
            Log.Trace("TlsUnwrap: Waiting for SSL/TLS authentication...");
        }
        Log.Debug("TlsUnwrap: SSL/TLS is authenticated, starting outgoing pump.");
        
        if (_socket is null)
        {
            Log.Critical("Lost socket in TlsUnwrap.BufferPumpOutgoing");
            _running = false;
            return;
        }
        
        // First, pick up the client's hello, and start doing the hand-shake
        while (_running)
        {
            // Keep trying to move data around between the plain and encrypted buffers.
            // _socket <-> _plainSideBuffer | unwrap | _encryptionSideBuffer <-> ISocketAdaptor methods

            try
            {
                var toWrite = _socket.OutgoingFromLocal(buffer);
                if (toWrite > 0)
                {
                    Log.Trace($"TlsUnwrap: Data from web app: {toWrite} bytes;\r\n{Bit.Describe("payload", buffer.Take(toWrite))}");
                    _sslStream.Write(buffer, 0, toWrite);
                    Log.Trace("TlsUnwrap: written.");
                }
                else Log.Trace("TlsUnwrap: no data from web app");

                if (toWrite < 1) Thread.Sleep(1);
            }
            catch (Exception ex)
            {
                Log.Debug($"Failure in TlsUnwrap.BufferPumpOutgoing. Probably shutdown related: {ex.Message}");
                Thread.Sleep(50);
            }
        }
    }

    /// <summary>Release the underlying socket</summary>
    public void Dispose()
    {
        _running = false;
        Close();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Close the underlying connection
    /// </summary>
    public void Close()
    {
        _running = false;
        try { _socket?.Dispose(); }
        catch (Exception ex) { Log.Error("TLS unwrap: Failed to dispose socket", ex); }

        try { _sslStream.Dispose(); }
        catch (Exception ex) { Log.Error("TLS unwrap: Failed to dispose SSL stream", ex); }
        
        var ok = _pumpThreadIncoming.Join(TimeSpan.FromMilliseconds(256));
        ok &= _pumpThreadOutgoing.Join(TimeSpan.FromMilliseconds(256));
        if (!ok)
        {
            Log.Warn("TLS unwrap: pump threads did not stop within time limit");
        }
    }

    /// <summary>
    /// True if the underlying socket is in a connected state
    /// </summary>
    public bool Connected => _socket?.Connected==true && _running;
    
    /// <summary>
    /// Number of bytes available to be read from <see cref="OutgoingFromLocal"/>
    /// </summary>
    public int Available => _tunnelSideBuffer.Available;
    
    
    /// <summary>
    /// Called externally. This should be data coming from the remote
    /// client. This is our 'hello' source, and will be encrypted.
    /// <p></p>
    /// Buffer is arbitrarily sized, and we return what we could read.
    /// <p></p>
    /// This is where we pretend to be a TLS Server
    /// </summary>
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        // Data incoming is what we should feed to our SslStream instance
        Log.Trace($"TlsUnwrap: IncomingFromTunnel({buffer.Length} bytes, offset={offset}, length={length})");
        return _tunnelSideBuffer.WriteIncomingNonBlocking(buffer, offset, length);
    }

    /// <summary>
    /// Called externally. This is where we supply the decoded data,
    /// ready to be moved to the other side by <see cref="TcpAdaptor"/>.
    /// <p></p>
    /// Buffer is expected to be at-most the size of <see cref="Available"/>
    /// and we should try to entirely fill it, returning the number of bytes
    /// copied.
    /// <p></p>
    /// This is where we pretend to be a TLS Server
    /// </summary>
    public int OutgoingFromLocal(byte[] buffer)
    {
        // Data outgoing is what we read from our SslStream instance
        Log.Trace($"TlsUnwrap: OutgoingFromLocal({buffer.Length} bytes)");
        return _tunnelSideBuffer.ReadNonBlocking(buffer);
    }

    public bool IsFaulted()
    {
        return _faulted || (_socket?.IsFaulted() ?? false);
    }

    #region Certificates

    private X509Certificate CertSelect(object sender, string? hostname)
    {
        if (_certificate is null) throw new Exception("TlsUnwrap.CertSelect: tried to select, but no certificate was loaded");
        Log.Trace($"Returning cert for {hostname??"<unknown>"} with {_certificate.Subject}");

        if (Platform.Current() == Platform.Kind.Windows)
        {
            // There are a bunch of bugs, and no-one seems to want to fix them.
            // See
            //  - https://github.com/dotnet/runtime/issues/23749
            //  - https://github.com/dotnet/runtime/issues/45680
            //  - https://github.com/dotnet/runtime/issues/23749
            //  - https://github.com/dotnet/runtime/issues/27826
            // These bugs were closed at time of writing, but not actually fixed.
            
            if (hostname is null || !_certificate.Subject.Contains(hostname))
                throw new Exception("Windows does not support providing certificates without matching 'CN'. " +
                                    "If you are testing, consider putting the DNS name in C:\\Windows\\System32\\drivers\\etc\\hosts file");
        }

        return _certificate;
    }
    

    private static X509Certificate GetX509Certificate(string privateKeyFile, string certificateFile)
    {
        var certPem = File.ReadAllText(certificateFile);
        var keyPem = File.ReadAllText(privateKeyFile);
        var certFromPem = X509Certificate2.CreateFromPem(certPem, keyPem);

        if (Platform.Current() != Platform.Kind.Windows) return certFromPem;
        
        return ReWrap(certFromPem);
    }

    /// <summary>
    /// Works around some of the many bugs in Windows cert store
    /// </summary>
    private static X509Certificate2 ReWrap(X509Certificate2 certFromPem)
    {
        return new X509Certificate2(certFromPem.Export(X509ContentType.Pkcs12));
    }

    #endregion
}