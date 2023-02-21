using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using VirtualVpn.Helpers;
using VirtualVpn.Logging;
using VirtualVpn.TcpProtocol;
using VirtualVpn.Web;

namespace VirtualVpn.TlsWrappers;

/// <summary>
/// Pretend that an API proxy call is a HTTP over TCP socket client.
/// This is the client version of <see cref="TlsUnwrap"/>.
/// This class specialises in HTTP protocol streams.
/// </summary>
public class TlsHttpProxyCallAdaptor : ISocketAdaptor
{
    private readonly HttpProxyRequest _request;
    private readonly object _transferLock = new();
    private readonly Uri _targetUri;
    
    // Document buffers (always plain-text)
    private readonly HttpBuffer _httpResponseBuffer;
    private readonly List<byte> _httpRequestBuffer;
    
    // Message buffers (may be plain or encrypted)
    private readonly BlockingBidirectionalBuffer _blockingBuffer;
    
    // SSL/TLS helpers
    private readonly Thread _messagePumpThread;
    private volatile bool _messagePumpRunning;
    private SslStream? _sslStream;

    /// <summary>
    /// Prepare a HTTP(S) call from a proxy request.
    /// </summary>
    /// <param name="request">HTTP request to make</param>
    /// <param name="useTls">If true, the message will be transmitted as HTTPS</param>
    public TlsHttpProxyCallAdaptor(HttpProxyRequest request, bool useTls)
    {
        _request = request;
        _targetUri = new Uri(request.Url, UriKind.Absolute);

        // We start in connected state, as we already have the proxy request
        Connected = true;
        
        _blockingBuffer = new BlockingBidirectionalBuffer();
        
        _httpRequestBuffer = new List<byte>((request.Body?.Length ?? 0) + 100);
        _httpResponseBuffer = new HttpBuffer();

        // Convert the request into a byte buffer
        _httpRequestBuffer.AddRange(Encoding.ASCII.GetBytes($"{request.HttpMethod} {_targetUri.PathAndQuery} HTTP/1.1\r\n"));
        if (!request.Headers.ContainsKey("Host"))
        {
            _httpRequestBuffer.AddRange(Encoding.ASCII.GetBytes($"Host: {_targetUri.Host}\r\n"));
        }

        foreach (var header in request.Headers)
        {
            _httpRequestBuffer.AddRange(Encoding.ASCII.GetBytes($"{header.Key}: {header.Value}\r\n"));
        }

        _httpRequestBuffer.AddRange(Encoding.ASCII.GetBytes("\r\n"));

        if (request.Body is not null)
        {
            _httpRequestBuffer.AddRange(request.Body);
        }


        _messagePumpRunning = true;
        _messagePumpThread = new Thread(useTls ? RunSslAdaptor : RunDirectAdaptor) { IsBackground = true };
        _messagePumpThread.Start();
    }

    ~TlsHttpProxyCallAdaptor()
    {
        _sslStream?.Dispose();
    }

    /// <summary>
    /// Run the blocking SSL/TLS adaptor, using
    /// blocking stream interface on this class.
    /// </summary>
    private void RunSslAdaptor()
    {
        try
        {
            Log.Trace($"Proxy: {nameof(RunSslAdaptor)}");
            _sslStream = new SslStream(_blockingBuffer, true);

            if (_sslStream.CanTimeout)
            {
                Log.Info("Proxy: Setting 30 second timeout on SSL/TLS connection");
                _sslStream.WriteTimeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
                _sslStream.ReadTimeout = (int)TimeSpan.FromSeconds(30).TotalMilliseconds;
            }
            
            // Make a best guess at who the authority will be
            var targetHost = _targetUri.Authority;
            if (_request.Headers.ContainsKey("Host"))
            {
                targetHost = _request.Headers["Host"];
            }

            // This will call our object's 'Write' and 'Read' methods
            // and this call will block until either the handshake is
            // complete, or it fails. If either the 'Read' or 'Write'
            // methods return without any data, the authentication is
            // immediately ended with an exception.
            var authOptions = new SslClientAuthenticationOptions{
                TargetHost = targetHost,
                EnabledSslProtocols = SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = AnyCertificate
            };
            
            _sslStream.AuthenticateAsClient(authOptions);
            Log.Trace("############ AUTHENTICATION EXCHANGE COMPLETE ############");

            // we should be connected. Write the request
            // and try to read back the response
            var rawRequest = _httpRequestBuffer.ToArray();
            Log.Trace("Proxy: SSL Outgoing request (plain)", () => Bit.Describe("Raw", rawRequest));
            
            if (Settings.CaptureTraffic)
            {
                var capNum = Interlocked.Increment(ref TlsUnwrap.CaptureNumber);
                File.WriteAllText(Settings.FileBase + $"Tls{capNum:0000}_proxy_out.txt",
                    Bit.Describe("payload", rawRequest)
                );
            }

            _sslStream.Write(rawRequest);

            Log.Trace($"Proxy: {nameof(RunSslAdaptor)}, authenticated and written");
            var buffer = new byte[8192];
            while (_messagePumpRunning && _sslStream is not null)
            {
                try
                {
                    var actual = _sslStream.Read(buffer, 0, buffer.Length);
                    var final = _httpResponseBuffer.FeedData(buffer, 0, actual);
                    Log.Trace($"Proxy received {final} bytes of a potential {actual} through SSL/TLS");
                    Log.Trace("Proxy: SSL incoming response", () => Bit.Describe("Raw", buffer, 0, actual));
                }
                catch (NullReferenceException nex)
                {
                    Log.Error("SSL read null-reference exception. Source stream is likely truncated. Ending message loop", nex);
                    break;
                }


                if (_httpResponseBuffer.IsComplete())
                {
                    Log.Trace("Proxy: SSL/TLS HTTP message complete");
                    EndConnection();
                }
            }

            try
            {
                _sslStream?.Close();
            }
            catch (Exception ex)
            {
                Log.Error("Error closing SSL stream in TlsHttpProxyCallAdaptor.RunSslAdaptor", ex);
            }

            if (Settings.CaptureTraffic)
            {
                var capNum = Interlocked.Increment(ref TlsUnwrap.CaptureNumber);
                File.WriteAllText(Settings.FileBase + $"Tls{capNum:0000}_proxy_in.txt",
                    Bit.Describe("payload", _httpResponseBuffer.RawIncomingData())
                );
            }

            Log.Trace($"Proxy: {nameof(RunSslAdaptor)} ended");
        }
        catch (Exception ex)
        {
            Log.Error("Failure in SSL Adaptor loop", ex);
            EndConnection();
        }
    }

    /// <summary>
    /// Transfer data between queues and buffers
    /// without waiting or doing transformations.
    /// </summary>
    private void RunDirectAdaptor()
    {
        Log.Info($"Proxy: Direct adaptor, request buffer={_httpRequestBuffer.Count} bytes, outgoingQueue={_blockingBuffer.Available} bytes");
        
        // Add everything to the outgoing queue
        lock (_transferLock)
        {
            var outData = _httpRequestBuffer.ToArray();
            if (Settings.CaptureTraffic)
            {
                var capNum = Interlocked.Increment(ref TlsUnwrap.CaptureNumber);
                File.WriteAllText(Settings.FileBase + $"Tls{capNum:0000}_proxy_out.txt",
                    Bit.Describe("payload", outData)
                );
            }
            _blockingBuffer.WriteOutgoingNonBlocking(outData);
            _httpRequestBuffer.Clear();
        }

        // Read back the incoming queue until the buffer is filled
        var buf = new byte[8192];
        while (_messagePumpRunning)
        {
            try
            {
                Log.Trace("Proxy direct (wait)");
                int read;

                lock (_transferLock)
                {
                    read = _blockingBuffer.Read(buf, 0, buf.Length);
                    Log.Info($"Proxy direct: transferring {read} bytes");
                }

                _httpResponseBuffer.FeedData(buf, 0, read);

                if (_httpResponseBuffer.IsComplete())
                {
                    Log.Trace("Proxy direct: document complete");
                    EndConnection();
                }
            }
            catch (Exception ex)
            {
                Log.Error("Failure in proxy adaptor: RunDirectAdaptor", ex);
            }
        }
        
        if (Settings.CaptureTraffic)
        {
            var capNum = Interlocked.Increment(ref TlsUnwrap.CaptureNumber);
            File.WriteAllText(Settings.FileBase + $"Tls{capNum:0000}_proxy_in.txt",
                Bit.Describe("payload", _httpResponseBuffer.RawIncomingData())
            );
        }
        Log.Info("Proxy direct: ended");
    }
    
    /// <summary>
    /// A helper that waits for either a timeout
    /// or the connection to complete.
    /// Returns true if the connection completed.
    /// </summary>
    public bool WaitForFinish(TimeSpan timeout)
    {
        var sw = new Stopwatch();
        sw.Start();
        while (sw.Elapsed < timeout)
        {
            if (!Connected) return true;
            Thread.Sleep(10);
        }
        return !Connected;
    }

    /// <summary>
    /// INTERFACE TO VPN TUNNEL
    /// <p></p>
    /// True if the adaptor is connected to its source
    /// </summary>
    public bool Connected { get; private set; }

    /// <summary>
    /// INTERFACE TO VPN TUNNEL
    /// <p></p>
    /// How much data does the local side have ready
    /// to send through the tunnel?
    /// </summary>
    public int Available => _blockingBuffer.Available;

    /// <summary>
    /// INTERFACE TO VPN TUNNEL
    /// <p></p>
    /// Data incoming from the tunnel, to write to local side
    /// This could be plain or encrypted. The message pump
    /// thread should deal with interpreting it.
    /// </summary>
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        return _blockingBuffer.WriteIncomingNonBlocking(buffer, offset, length);
    }

    /// <summary>
    /// INTERFACE TO VPN TUNNEL
    /// <p></p>
    /// Read data from local side to send through the tunnel.
    /// This could be plain or encrypted. The message pump
    /// thread should deal with interpreting it.
    /// </summary>
    public int OutgoingFromLocal(byte[] buffer)
    {
        return _blockingBuffer.ReadNonBlocking(buffer);
    }

    public bool IsFaulted()
    {
        return false;
    }

    /// <summary>
    /// Build a response object from what has been received so far.
    /// </summary>
    public HttpProxyResponse GetResponse()
    {
        return _httpResponseBuffer.GetResponseObject();
    }

    /// <summary>
    /// Shut down this connection
    /// </summary>
    private void EndConnection()
    {
        try
        {
            Log.Trace("HttpProxyCallAdaptor: EndConnection");

            Connected = false;
            try
            {
                if (_messagePumpRunning) _sslStream?.Close();
            }
            catch (Exception ex)
            {
                Log.Error("Failure when trying to end connection", ex);
            }

            _messagePumpRunning = false;
            _blockingBuffer.Close();

            var cleanEnd = _messagePumpThread.Join(500);
            if (!cleanEnd)
            {
                Log.Warn("Proxy call adaptor did not end correctly (_messagePumpThread.Join timed out)");
            }

            Log.Trace("HttpProxyCallAdaptor: Connection closed");
        }
        catch (Exception ex)
        {
            Log.Error("Error in TlsHttpProxyCallAdaptor.EndConnection", ex);
        }
    }
    
    /// <summary>
    /// Accept any server certificate
    /// </summary>
    private static bool AnyCertificate(object a, X509Certificate? b, X509Chain? c, SslPolicyErrors d) => true;


    /// <summary>
    /// Close the adaptor and its source
    /// </summary>
    public void Close()
    {
        Log.Trace($"{nameof(TlsHttpProxyCallAdaptor)}: Close called");
        _sslStream?.Dispose();
        _sslStream = null;
        EndConnection();
    }
    
    /// <summary>
    /// Close the adaptor and its source
    /// </summary>
    public void Dispose() {
        Log.DebugWithStack($"{nameof(TlsHttpProxyCallAdaptor)}: Dispose called");
        Close();
        GC.SuppressFinalize(this);
    }

}