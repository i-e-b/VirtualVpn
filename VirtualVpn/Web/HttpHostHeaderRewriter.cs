using System.Text;

namespace VirtualVpn.Web;

/// <summary>
/// An interceptor that will pass HTTP requests along,
/// and change the Host header to a new value
/// </summary>
public class HttpHostHeaderRewriter
{
    private byte[]? _lastTail;
    private readonly byte[] _newHostHeaderLine;
    private bool _done, _first;

    private static readonly byte[] _httpMarker = Encoding.ASCII.GetBytes("HTTP/");
    private static readonly byte[] _hostMarker = Encoding.ASCII.GetBytes("Host: ");
    private static readonly byte[] _doubleNewLine = Encoding.ASCII.GetBytes("\r\n\r\n");
    private static readonly byte[] _degenerateDoubleNewLine = Encoding.ASCII.GetBytes("\n\n");

    public HttpHostHeaderRewriter(string realHost)
    {
        _done = false;
        _first = true;
        _lastTail = null;
        _newHostHeaderLine = Encoding.ASCII.GetBytes($"Host: {realHost}\r\n");
    }

    /// <summary>
    /// Translate the incoming buffer and range into an outgoing buffer and range
    /// </summary>
    public byte[] Process(byte[] buffer, ref int offset, ref int length)
    {
        if (_done) return buffer; // feed the rest through without changes
        
        Log.Trace("HttpHostHeaderRewriter: looking for host header");
        
        // handle offset and length being non-standard
        var span = BufferSpanWithJoin(_lastTail, buffer, offset, length);
        
        // If this is the first chunk, look for HTTP stuff-- if we see 'HTTP/', it's probably ok
        if (_first)
        {
            _first = false;
            if (!Contains(span, _httpMarker, out _)) // this probably isn't HTTP
            {
                Log.Trace("HttpHostHeaderRewriter: request isn't HTTP? Ignoring");
                _done = true;
                return buffer;
            }
        }
        
        // Scan for "Host: "
        if (Contains(span, _hostMarker, out var start))
        {
            // See if we have the whole of the header line
            var end = FindLineEnd(span, start);

            if (end > start) // we have the whole header in one chunk. Do it the easy way
            {
                // Copy up to this point, replace.
                var newBuffer = CopyWithReplace(span, start, end);
                
                Log.Trace("HttpHostHeaderRewriter: found header in a complete block. Rewriting");

                _done = true;
                offset = 0;
                length = newBuffer.Length;
                return newBuffer;
            }
        }

        // Did not find Host, or we don't have the entire line.
        // Look for "\r\n\r\n", which would mean we have the whole headers, but no Host line.
        if (Contains(span, _doubleNewLine, out _) || Contains(span, _degenerateDoubleNewLine, out _))
        {
            Log.Trace("HttpHostHeaderRewriter: found end of headers without Host.");
            _done = true;
            return buffer;
        }

        // If we get here, we don't have the full set of headers in one packet.
        // This is the tricky case. We will buffer up as many lines as we can,
        // And scan each line as a unit, releasing scanned lines as we go.
        var lines = SplitLines(span);
        var output = new List<byte>();
        
        // Feed through all but the last line, keep the last as the next partial
        for (var index = 0; index < lines.Count - 1; index++)
        {
            var line = lines[index];
            if (Contains(line, _hostMarker, out _))
            {
                Log.Trace("HttpHostHeaderRewriter: found host header in fragments");
                _done = true;
                output.AddRange(_newHostHeaderLine);
            }
            else output.AddRange(line);
        }
        
        // either we found it, or we need to keep data for next round
        if (_done) output.AddRange(lines[^1]);
        else _lastTail = lines[^1];

        
        Log.Trace($"HttpHostHeaderRewriter: returning partial fragments. Found header={_done}");
        
        var partialBuffer = output.ToArray();
        offset = 0;
        length = partialBuffer.Length;
        return partialBuffer;
    }

    private static Span<byte> BufferSpanWithJoin(byte[]? tail, byte[] buffer, int offset, int length)
    {
        if (tail is null || tail.Length < 1) return buffer.AsSpan(offset, length);
        return tail.Concat(buffer.Skip(offset).Take(length)).ToArray().AsSpan();
    }

    /// <summary>
    /// Split into segments ending with either "\r\n" or "\n"
    /// Segments are not trimmed.
    /// </summary>
    private List<byte[]> SplitLines(Span<byte> span)
    {
        var output = new List<byte[]>();
        
        bool nl = false; // in a new line block
        int left = 0; // left edge
        int i = 0;
        for (; i < span.Length; i++)
        {
            var c = span[i];
            if (c == 0x0D || c == 0x0A)
            {
                nl = true;
            }
            else
            {
                if (nl) // end of new lines, cut and reset
                {
                    output.Add(span.Slice(left, i - left).ToArray());
                    left = i;
                    nl = false;
                }
                // else continuing chars
            }
        }

        if (left < i)
        {
            output.Add(span.Slice(left, i - left).ToArray());
        }

        return output;
    }

    private byte[] CopyWithReplace(Span<byte> span, int start, int end)
    {
        var result = new List<byte>();
        result.AddRange(span[..start].ToArray()); //.Take(start));
        result.AddRange(_newHostHeaderLine);
        result.AddRange(span[(end + 1)..].ToArray()); //.Skip(end+1));
        var newBuffer = result.ToArray();
        return newBuffer;
    }

    private static int FindLineEnd(Span<byte> span, int start)
    {
        var bufferEnd = span.Length - 1;
        var end = start + 6;
        while (end < span.Length)
        {
            if (span[end] == 0x0D)
            {
                if (end < bufferEnd && span[end + 1] == 0x0A) // correct end
                {
                    end += 1;
                }

                return end;
            }

            if (span[end] == 0x0A) // degenerate end
            {
                return end;
            }

            end++;
        }

        return -1; // not found
    }

    public static bool Contains(Span<byte> haystack, Span<byte> needle, out int position)
    {
        position = -1;
        var nEnd = needle.Length - 1;
        int i = nEnd;
        while (i < haystack.Length)
        {
            if (haystack[i] != needle[nEnd]) // can't be the end
            {
                if (haystack[i] == needle[0]) i += nEnd; // might be the start
                else i++; // can't be the start
                continue;
            }

            // Candidate: scan
            var found = true;
            position = i - nEnd;
            for (int j = 0; j <= nEnd; j++)
            {
                if (haystack[i - j] != needle[nEnd - j]) // mismatch, jump again
                {
                    i+= nEnd;
                    found = false;
                    break;
                }
            }
            
            if (found) return true;
        }
        position = -1;
        return false;
    }
}