using System.Globalization;
using System.Text;
using VirtualVpn.TcpProtocol;

namespace VirtualVpn.Web;

/// <summary>
/// Pretend that an API proxy call is a HTTP over TCP socket client
/// This does unsecured calls only at the moment.
/// TODO: support HTTPS (SslSocketStream)
/// </summary>
public class HttpProxyCallAdaptor : ISocketAdaptor
{
    private readonly HttpProxyResponse _response;
    private int _dataSent;
    private readonly int _totalSize;
    private readonly List<byte> _outgoingBuffer, _incomingBuffer;

    public HttpProxyCallAdaptor(HttpProxyRequest request, HttpProxyResponse response)
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
            var uri = new Uri(request.Url, UriKind.Absolute);
            _outgoingBuffer.AddRange(Encoding.ASCII.GetBytes($"Host: {uri.Host}\r\n"));
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
        var expectedLength = 0;
        while ((line = ReadLine(ref cursor)) != "")
        {
            var sp = line.IndexOf(": ", StringComparison.Ordinal);
            if (sp < 1) break; // invalid
            var key = line.Substring(0, sp);
            var value = line.Substring(sp + 2).Trim(); // should have "\r\n" at end, which we remove.

            if (key == "Content-Length")
            {
                int.TryParse(value, out expectedLength);
            }

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
        var endedCorrectly = false;
        if (cursor < _incomingBuffer.Count)
        {
            if (_response.Headers.ContainsKey("Transfer-Encoding")
                && _response.Headers["Transfer-Encoding"].Contains("chunked"))
            {
                _response.Body = DecodeChunked(cursor, ref endedCorrectly);
            }
            else
            {
                _response.Body = _incomingBuffer.Skip(cursor).ToArray();
                endedCorrectly = _response.Body.Length == expectedLength;
            }
        }
        else
        { 
            endedCorrectly = _response.Headers.ContainsKey("Content-Length") && _response.Headers["Content-Length"] == "0";
        }

        if (!endedCorrectly)
        {
            _response.Success = false;
            _response.ErrorMessage = "Body was truncated";
        }
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

        // Try to see if we have a complete http call.
        TryToDetectEndOfDocument();

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
    

    /// <summary>
    /// Try to see if we have a complete http call.
    /// </summary>
    /// <remarks>TCP has no concept of the end of a stream, so we have to guess from headers + body, or wait for a timeout </remarks>
    private void TryToDetectEndOfDocument()
    {
        var cursor = 0;
        var line = ReadLine(ref cursor);
        if (string.IsNullOrEmpty(line)) return;

        // Try to read headers
        var checkChunks = false; // set this if we find a "Transfer-Encoding: chunked" header
        while ((line = ReadLine(ref cursor)) != "")
        {
            var sp = line.IndexOf(": ", StringComparison.Ordinal);
            if (sp < 1) break; // invalid
            var key = line.Substring(0, sp);
            var value = line.Substring(sp + 2);

            // Check for defined-length message
            if (key == "Content-Length"
                && int.TryParse(value, out var declaredLength))
            {
                var endOfHeader = cursor - 1;
                var bodySizeGuess = _incomingBuffer.Count - endOfHeader;
                Log.Trace($"Saw content length={declaredLength}. Currently have {_incomingBuffer.Count} bytes in buffer, with {endOfHeader} of header.");
                if (bodySizeGuess >= declaredLength)
                {
                    Log.Trace($"Ending connection based on length: declared {declaredLength}, got {bodySizeGuess}");

                    // We have a complete document! Flip the switch:
                    EndConnection();
                }

                return; // don't need to read any more headers, we know we're not finished.
            }

            // Checked for a chunked transfer
            if (key == "Transfer-Encoding" && value.Contains("chunked"))
            {
                checkChunks = true;
                // don't break out early, so we consume the rest of the headers
            }
        }

        // We're in a chunked scenario, so we have to
        // walk all the chunks until we see the end marker: "0\r\n\r\n" 
        // As the end marker is also valid data, we can't naïvely.
        // scan 
        if (checkChunks)
        {
            while ((line = ReadLine(ref cursor)) != "")
            {
                var length = ReadChunkLength(line);
                if (length < 0) return; // could not read line -- probably not yet complete
                if (length == 0) // marker for end of document
                {
                    Log.Trace("Ending connection based on zero-length chunk");

                    // We have a complete document! Flip the switch:
                    EndConnection();
                    return;
                }

                // We have a non-zero length. Try to skip.
                // If we go off the end of the buffer, `ReadLine`
                // should catch it
                cursor += length + 2; // Chunk data should have "\r\n" terminator
            }
        }

        // Not end of document. Do nothing.
    }

    /// <summary>
    /// Decode a chunked body into a plain byte array
    /// </summary>
    // ReSharper disable once RedundantAssignment
    private byte[] DecodeChunked(int start, ref bool endedCorrectly)
    {
        var cursor = start;
        var body = new List<byte>();
        while (true)
        {
            var line = ReadLine(ref cursor);
            var length = ReadChunkLength(line);
            if (length < 0)
            {
                endedCorrectly = false;
                break; // could not read line. Maybe truncated
            }

            // prevent truncation causing an error
            if (cursor + length > _incomingBuffer.Count)
            {
                endedCorrectly = false;
                length = _incomingBuffer.Count - cursor;
            }
            
            if (length == 0) // marker for end of document
            {
                endedCorrectly = true;
                break; // note, we do not support "trailing" headers
            }

            // We have a non-zero length. Copy and move forward
            body.AddRange(_incomingBuffer.GetRange(cursor, length));
            cursor += length + 2; // Chunk data should have "\r\n" terminator
        }
        return body.ToArray();
    }

    private int ReadChunkLength(string line)
    {
        if (!line.EndsWith("\r\n")) return -1; // invalid line -- probably got cut short

        var bits = line.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (bits.Length < 1) return -1; // Empty?
        
        var ok = int.TryParse(bits[0], NumberStyles.HexNumber, null, out var length);
        if (!ok) return -1; // Not parsable
        
        return length; // Looks like a valid chunk spec
    }
    
    /// <summary>
    /// Read from the cursor to the next line end.
    /// Cursor is updated to point to first character on next line
    /// </summary>
    private string ReadLine(ref int cursor)
    {
        var start = cursor;
        var end = _incomingBuffer.Count - 1;
        for (int i = start; i <= end; i++)
        {
            if (_incomingBuffer[i] == 0x0D) // it's a new-line. Might be [0D] or [0A] or [0D0A]
            {
                cursor = i + 1;
                if (i < end && _incomingBuffer[i + 1] == 0x0A) cursor++;
                break;
            }

            if (_incomingBuffer[i] == 0x0A)
            {
                // Non-conforming new line
                cursor = i + 1;
                break;
            }
        }

        if (start >= cursor) return "";
        return Encoding.UTF8.GetString(_incomingBuffer.GetRange(start, cursor - start).ToArray());
    }
}