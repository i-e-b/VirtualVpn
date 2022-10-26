using System.Globalization;
using System.Text;

namespace VirtualVpn.Web;

/// <summary>
/// A byte buffer that understands just enough
/// of the HTTP protocol to know when a stream
/// has been completed.
/// </summary>
public class HttpBuffer
{
    private readonly List<byte> _incomingBuffer;

    /// <summary>
    /// Create a new empty HTTP buffer
    /// </summary>
    public HttpBuffer()
    {
        _incomingBuffer = new List<byte>();
    }

    /// <summary>
    /// Number of bytes buffered
    /// </summary>
    public long Length => _incomingBuffer.Count;

    /// <summary>
    /// Feed data into the buffer
    /// </summary>
    /// <param name="buffer">byte buffer to feed from</param>
    /// <param name="offset">offset into the buffer where data starts</param>
    /// <param name="length">number of bytes to copy</param>
    /// <returns>number of bytes copied</returns>
    public int FeedData(byte[] buffer, int offset, int length)
    {
        if (length <= 0) return 0;
        
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
    /// Returns true if the document has been completed
    /// </summary>
    public bool IsComplete()
    {
        var cursor = 0;
        var line = ReadLine(ref cursor);
        if (string.IsNullOrEmpty(line)) return false;

        // Try to read headers
        var checkChunks = false; // set this if we find a "Transfer-Encoding: chunked" header
        while ((line = ReadLine(ref cursor)) != "")
        {
            var sp = line.IndexOf(": ", StringComparison.Ordinal);
            if (sp < 1) break; // invalid
            var key = line.Substring(0, sp);
            var value = line.Substring(sp + 2);

            // Check for defined-length message
            if (key.ToLowerInvariant() == "content-length" // note: I am seeing malformed headers from some callers.
                && int.TryParse(value, out var declaredLength))
            {
                if (key != "Content-Length")
                {
                    Log.Warn($"Invalid casing on content length header: '{key}'. This may cause downstream to fault");
                }

                var endOfHeader = cursor - 1;
                var bodySizeGuess = Length - endOfHeader;
                Log.Trace($"Saw content length={declaredLength}. Currently have {Length} bytes in buffer, with {endOfHeader} of header.");
                if (bodySizeGuess >= declaredLength)
                {
                    Log.Trace($"Ending connection based on length: declared {declaredLength}, got {bodySizeGuess}");

                    // We have a complete document! Flip the switch:
                    return true;
                }

                return false; // don't need to read any more headers, we know we're not finished.
            }

            // Checked for a chunked transfer
            if (key.ToLowerInvariant() == "transfer-encoding" && value.Contains("chunked"))
            {
                if (key != "Transfer-Encoding")
                {
                    Log.Warn($"Invalid casing on encoding header: '{key}'. This may cause downstream to fault");
                }
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
                if (length < 0) return false; // could not read line -- probably not yet complete
                if (length == 0) // marker for end of document
                {
                    Log.Trace("Ending connection based on zero-length chunk");

                    // We have a complete document! Flip the switch:
                    return true;
                }

                // We have a non-zero length. Try to skip.
                // If we go off the end of the buffer, `ReadLine`
                // should catch it
                cursor += length + 2; // Chunk data should have "\r\n" terminator
            }
        }

        // Not end of document.
        return false;
    }

    /// <summary>
    /// Decode the response into a HTTP proxy object
    /// </summary>
    public HttpProxyResponse GetResponseObject()
    {
        var response = new HttpProxyResponse();
        // Read initial status line
        var cursor = 0;
        var firstLine = ReadLine(ref cursor);
        var status = firstLine.Split(new[] { ' ' }, 3, StringSplitOptions.TrimEntries);

        if (status.Length < 2 || !firstLine.StartsWith("HTTP/1.1")) // probably completely wrong
        {
            response.StatusCode = 502; // "bad gateway"
            response.StatusDescription = "Unexpected protocol error";
            response.Success = false;
            response.ErrorMessage = $"Did not find 'HTTP/1.1' marker. First line was '{firstLine}'";
            return response;
        }

        response.Success = true;
        var ok = int.TryParse(status[1], out var statusCode);
        if (!ok)
        {
            statusCode = 502;
            response.Success = false;
        }

        response.StatusCode = statusCode;
        response.StatusDescription = (status.Length > 2) ? status[2] : "";

        // Read headers until we hit a blank line
        string line;
        var expectedLength = 0;
        while ((line = ReadLine(ref cursor)) != "")
        {
            var sp = line.IndexOf(": ", StringComparison.Ordinal);
            if (sp < 1) break; // invalid
            var key = line.Substring(0, sp);
            var value = line.Substring(sp + 2).Trim(); // should have "\r\n" at end, which we remove.

            var lowerKey = key.ToLowerInvariant();
            if (lowerKey == "content-length")
            {
                key = "Content-Length"; // normalise bad headers
                int.TryParse(value, out expectedLength);
            }

            if (lowerKey == "transfer-encoding") key = "Transfer-Encoding"; // normalise bad headers
            if (lowerKey == "content-type") key = "Content-Type"; // normalise bad headers

            if (response.Headers.ContainsKey(key))
            {
                response.Headers[key] += ", " + value;
            }
            else
            {
                response.Headers.Add(key, value);
            }
        }

        // Now we should have enough details to read the body correctly.
        var endedCorrectly = false;
        if (cursor < Length)
        {
            if (response.Headers.ContainsKey("Transfer-Encoding")
                && response.Headers["Transfer-Encoding"].Contains("chunked"))
            {
                Log.Info("Decoding chunked message");
                response.Body = DecodeChunked(cursor, ref endedCorrectly);
            }
            else
            {
                response.Body = _incomingBuffer.Skip(cursor).ToArray();
                endedCorrectly = response.Body.Length == expectedLength;
                Log.Debug($"Decoding body. Read {response.Body.Length} bytes, expected {expectedLength} bytes");
                if (!endedCorrectly)
                {
                    Log.Warn($"Unexpected HTTP length. Buffer={_incomingBuffer.Count}, Cursor={cursor}, Expected={expectedLength}, Read={response.Body.Length}");
                }
            }
        }
        else
        { 
            endedCorrectly = response.Headers.ContainsKey("Content-Length") && response.Headers["Content-Length"] == "0";
        }

        if (!endedCorrectly)
        {
            response.Success = false;
            response.ErrorMessage = "Body was truncated";
        }
        return response;
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
            if (cursor + length > Length)
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

    /// <summary>
    /// Return a copy of all received data so far
    /// </summary>
    public byte[] RawIncomingData() => _incomingBuffer.ToArray();
}