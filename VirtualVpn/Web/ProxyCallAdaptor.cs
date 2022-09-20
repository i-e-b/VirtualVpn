using System.Text;
using VirtualVpn.TcpProtocol;

namespace VirtualVpn.Web;

/// <summary>
/// Pretend that an API proxy call is a TCP socket client
/// This does unsecured calls only at the moment.
/// TODO: support HTTPS (SslSocketStream)
/// </summary>
public class ProxyCallAdaptor : ISocketAdaptor
{
    private readonly HttpProxyResponse _response;
    private int _dataSent;
    private readonly int _totalSize;
    private readonly List<byte> _outgoingBuffer, _incomingBuffer;
    
    public ProxyCallAdaptor(HttpProxyRequest request, HttpProxyResponse response)
    {
        _response = response;
        _dataSent = 0;
        _response.StatusCode = 0;

        _outgoingBuffer = new List<byte>((request.Body?.Length ?? 0) + 100);
        _incomingBuffer = new List<byte>();
        
        // Convert the request into a byte buffer
        _outgoingBuffer.AddRange(Encoding.ASCII.GetBytes($"{request.HttpMethod} {request.Url} HTTP/1.1\r\n"));
        if (!request.Headers.ContainsKey("Host"))
        {
            _outgoingBuffer.AddRange(Encoding.ASCII.GetBytes($"Host: {request.TargetMachineIp}\r\n"));
        }

        foreach (var header in request.Headers)
        {
            _outgoingBuffer.AddRange(Encoding.ASCII.GetBytes($"{header.Key}: {header.Value}\r\n"));
        }
        
        _outgoingBuffer.AddRange(Encoding.ASCII.GetBytes("\r\n"));

        if (request.Body is not null)
        {
            _outgoingBuffer.AddRange(request.Body);
        }

        _totalSize = _outgoingBuffer.Count;
        Connected = true;
    }

    private void EndConnection()
    {
        Connected = false;

        if (_response.StatusCode > 0) return; // already converted

        // Read initial status line
        var cursor = 0;
        var firstLine = ReadLine(ref cursor);
        var status = firstLine.Split(new[] { ' ' }, 3, StringSplitOptions.TrimEntries);

        if (status.Length < 2 || !firstLine.StartsWith("HTTP/1.1")) // probably completely wrong
        {
            _response.StatusCode = 502; // "bad gateway"
            _response.StatusDescription = "Unexpected protocol error";
            _response.Success = false;
            _response.ErrorMessage = $"Did not find 'HTTP/1.1' marker. First line was '{firstLine}'";
            return;
        }

        _response.Success = true;
        var ok = int.TryParse(status[1], out var statusCode);
        if (!ok)
        {
            statusCode = 502;
            _response.Success = false;
        }

        _response.StatusCode = statusCode;
        _response.StatusDescription = (status.Length > 2) ? status[2] : "";
        
        // Read headers until we hit a blank line
        string line;
        while ((line = ReadLine(ref cursor)) != "")
        {
            var sp = line.IndexOf(": ", StringComparison.Ordinal);
            if (sp < 1) break; // invalid
            var key = line.Substring(0, sp);
            var value = line.Substring(sp+2);
            if (_response.Headers.ContainsKey(key))
            {
                _response.Headers[key] += ", " + value;
            }
            else
            {
                _response.Headers.Add(key, value);
            }
        }
        
        // Now we should have enough details to read the body correctly.
        // Until it becomes needed, we just copy all the remains across.

        if (cursor < _incomingBuffer.Count)
        {
            _response.Body = _incomingBuffer.Skip(cursor).ToArray();
        }
    }

    /// <summary>
    /// Read from the cursor to the next line end
    /// </summary>
    private string ReadLine(ref int cursor)
    {
        var start = cursor;
        var end = _incomingBuffer.Count - 1;
        for (int i = start; i <= end; i++)
        {
            if (_incomingBuffer[i] == 0x0D)// it's a new-line. Might be [0D] or [0A] or [0D0A]
            {
                cursor = i;
                if (i < end && _incomingBuffer[i + 1] == 0x0A) cursor++;
                break;
            }

            if (_incomingBuffer[i] == 0x0A)
            {
                // Non-conforming new line
                cursor = i;
                break;
            }
        }
        if (start >= cursor) return "";
        return Encoding.UTF8.GetString(_incomingBuffer.GetRange(start, cursor - start).ToArray());
    }

    public void Dispose() => EndConnection();

    public void Close() => EndConnection();

    /// <summary>
    /// True if the adaptor is connected to its source
    /// </summary>
    public bool Connected { get; private set; }

    /// <summary>
    /// How much data does the local side have ready
    /// to send through the tunnel?
    /// </summary>
    public int Available => _dataSent < _totalSize ? _totalSize - _dataSent : 0;


    /// <summary>
    /// Data incoming from the tunnel, to write to local side
    /// </summary>
    public int IncomingFromTunnel(byte[] buffer, int offset, int length)
    {
        var sent = length;
        var available = buffer.Length - offset;
        if (sent > available) sent = available;

        var bi = offset;
        for (int i = 0; i < sent; i++)
        {
            _incomingBuffer.Add(buffer[bi++]);
        }
        
        return sent;
    }

    /// <summary>
    /// Read data from local side to send through the tunnel
    /// </summary>
    public int OutgoingFromLocal(byte[] buffer)
    {
        var end = buffer.Length;
        var available = _outgoingBuffer.Count - _dataSent;
        if (end > available) end = available;
        
        for (int i = 0; i < end; i++)
        {
            buffer[i] = _outgoingBuffer[_dataSent++];
        }
        return end;
    }
}