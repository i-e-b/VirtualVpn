using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using VirtualVpn.TcpProtocol;

namespace VirtualVpn.Web;

/// <summary>
/// Pretend that an API proxy call is a HTTP over TCP socket client
/// </summary>
public class HttpProxyCallAdaptor : Stream, ISocketAdaptor
{
    private readonly object _transferLock = new();
    private readonly Uri _targetUri;
    
    // Document buffers (always plain-text)
    private readonly HttpBuffer _httpResponseBuffer;
    private readonly List<byte> _httpRequestBuffer;
    
    // Message buffers (may be plain or encrypted)
    private readonly List<byte> _outgoingQueue;
    private int _outgoingQueueSent;
    private readonly List<byte> _incomingQueue;
    private int _incomingQueueRead;
    
    // SSL/TLS helpers
    private readonly Thread _messagePumpThread;
    private volatile bool _messagePumpRunning;
    private SslStream? _sslStream;

    /// <summary>
    /// Prepare a HTTP(S) call from a proxy request.
    /// </summary>
    /// <param name="request">HTTP request to make</param>
    /// <param name="useTls">If true, the message will be transmitted as HTTPS</param>
    public HttpProxyCallAdaptor(HttpProxyRequest request, bool useTls)
    {
        _targetUri = new Uri(request.Url, UriKind.Absolute);
        _outgoingQueueSent = 0;

        // We start in connected state, as we already have the proxy request
        Connected = true;
        
        _outgoingQueue = new List<byte>();
        _incomingQueue = new List<byte>();
        
        _httpRequestBuffer = new List<byte>((request.Body?.Length ?? 0) + 100);
        _httpResponseBuffer = new HttpBuffer();

        if (useTls)
        {
            _messagePumpRunning = true;
            _messagePumpThread = new Thread(RunSslAdaptor){
                IsBackground = true
            };
        }
        else
        {
            _messagePumpRunning = true;
            _messagePumpThread = new Thread(RunDirectAdaptor){
                IsBackground = true
            };
        }

        // Convert the request into a byte buffer
        _httpRequestBuffer.AddRange(Encoding.ASCII.GetBytes($"{request.HttpMethod} {request.Url} HTTP/1.1\r\n"));
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

    }

    /// <summary>
    /// Run the blocking SSL/TLS adaptor, using
    /// blocking stream interface on this class.
    /// </summary>
    private void RunSslAdaptor()
    {
        _sslStream = new SslStream(this, true, AnyCertificate);
        
        // This will call our object's 'Write' and 'Read' methods
        // and this call will block until either the handshake is
        // complete, or it fails. If either the 'Read' or 'Write'
        // methods return without any data, the authentication is
        // immediately ended with an exception.
        _sslStream.AuthenticateAsClient(_targetUri.Host);

        // we should be connected. Write the request
        // and try to read back the response
        _sslStream.Write(_httpRequestBuffer.ToArray());
        
        var buffer = new byte[8192];
        while (_messagePumpRunning)
        {
            // TODO: a time-out here?
            var actual = _sslStream.Read(buffer, 0, buffer.Length);
            var final = _httpResponseBuffer.FeedData(buffer, 0, actual);
            Log.Trace($"Proxy received {final} bytes of a potential {actual} through SSL/TLS");
        }
        _sslStream.Close();
    }
    
    /// <summary>
    /// Transfer data between queues and buffers
    /// without waiting or doing transformations.
    /// </summary>
    private void RunDirectAdaptor()
    {
        // Add everything to the outgoing queue
        lock (_transferLock)
        {
            _outgoingQueue.AddRange(_httpRequestBuffer);
        }

        // Read back the incoming queue until the buffer is filled
        while (_messagePumpRunning)
        {
            if (_incomingQueue.Count < 1)
            {
                Thread.Sleep(50);
                continue;
            }

            byte[] buf;
            lock (_transferLock)
            {
                buf = _incomingQueue.ToArray();
                _incomingQueue.Clear();
            }

            _httpResponseBuffer.FeedData(buf, 0, buf.Length);
        }
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
    public int Available => _outgoingQueueSent < _outgoingQueue.Count ? _outgoingQueue.Count - _outgoingQueueSent : 0;

    /// <summary>
    /// INTERFACE TO VPN TUNNEL
    /// <p></p>
    /// Data incoming from the tunnel, to write to local side
    /// This could be plain or encrypted.
    /// </summary>
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        lock (_transferLock)
        {
            if (length <= 0) return 0;

            var sent = length;
            var available = buffer.Length - offset;
            if (sent > available) sent = available;

            var bi = offset;
            for (int i = 0; i < sent; i++)
            {
                _incomingQueue.Add(buffer[bi++]);
            }

            return sent;
        }
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
        lock (_transferLock)
        {
            var available = _outgoingQueue.Count - _outgoingQueueSent;

            if (available < 1) return 0;

            var end = buffer.Length;
            if (end > available) end = available;

            for (int i = 0; i < end; i++)
            {
                buffer[i] = _outgoingQueue[_outgoingQueueSent++];
            }

            if (_outgoingQueueSent >= _outgoingQueue.Count)
            {
                _outgoingQueueSent = 0;
                _outgoingQueue.Clear();
            }

            return end;
        }
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
        if (_messagePumpRunning) _sslStream?.Close();
        
        Connected = false;
        _messagePumpRunning = false;
        
        var cleanEnd = _messagePumpThread.Join(250);
        if (!cleanEnd)
        {
            Log.Warn("Proxy call SSL/TLS adaptor did not end correctly");
        }
    }
    
    /// <summary>
    /// Accept any server certificate
    /// </summary>
    private static bool AnyCertificate(object a, X509Certificate? b, X509Chain? c, SslPolicyErrors d) => true;
    
    #region Stream interface for SslStream
    /// <summary>
    /// Waits for outgoing queue to empty
    /// </summary>
    public override void Flush()
    {
        Log.Trace("Proxy: Flush (wait)");
        while (_outgoingQueue.Count > 0)
        {
            Thread.Sleep(50);
        }
        Log.Trace("Proxy: Flush complete");
    }

    /// <summary>
    /// Wait for data to be available in the incoming queue,
    /// then feed as much as possible into the buffer.
    /// </summary>
    public override int Read(byte[] buffer, int offset, int count)
    {
        Log.Trace("Proxy: Read (wait)");
        while (true)
        {
            lock (_transferLock)
            {
                if (_incomingQueue.Count > _incomingQueueRead) break;
            }
        }


        lock (_transferLock)
        {
            var available = _incomingQueue.Count - _incomingQueueRead;
            var bytesToCopy = available > count ? count : available;
            
            Log.Trace($"Proxy: Read (copying {bytesToCopy} bytes)");
            for (int i = 0; i < bytesToCopy; i++)
            {
                buffer[i+offset] = _incomingQueue[_incomingQueueRead++];
            }

            if (_incomingQueueRead >= _incomingQueue.Count)
            {
                _incomingQueue.Clear();
                _incomingQueueRead = 0;
            }
            
            Log.Trace("Proxy: Read complete");
            return bytesToCopy;
        }
    }

    /// <summary>
    /// Not supported
    /// </summary>
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Not supported
    /// </summary>
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    /// <summary>
    /// Push data to output queue, then wait for it to empty
    /// </summary>
    public override void Write(byte[] buffer, int offset, int count)
    {
        Log.Trace("Proxy: Write");

        lock (_transferLock)
        {
            if (offset == 0 && count == buffer.Length) _outgoingQueue.AddRange(buffer);
            else _outgoingQueue.AddRange(buffer.Skip(offset).Take(count));
        }

        Log.Trace("Proxy: Write (wait)");
        while (true)
        {
            lock (_transferLock)
            {
                if (_outgoingQueue.Count < 1) break;
            }
        }

        Log.Trace("Proxy: Write complete");
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => _httpResponseBuffer.Length;
    
    /// <summary>
    /// Not supported
    /// </summary>
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    /// <summary>
    /// <see cref="Stream"/> steals 'Dispose' and gives us 'Close'
    /// </summary>
    public override void Close() => EndConnection();
    #endregion
}