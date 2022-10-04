using System.Text;

namespace VirtualVpn.Web;

/// <summary>
/// An interceptor that will pass HTTP requests along,
/// and change the Host header to a new value
/// </summary>
public class HttpHostHeaderRewriter
{
    private readonly byte[] _realHost;
    private bool _done, _first;

    private static readonly byte[] _httpMarker = Encoding.ASCII.GetBytes("HTTP/");
    private static readonly byte[] _hostMarker = Encoding.ASCII.GetBytes("Host: ");

    public HttpHostHeaderRewriter(string realHost)
    {
        _done = false;
        _first = true;
        _realHost = Encoding.ASCII.GetBytes($"Host: {realHost}\r\n");
    }

    /// <summary>
    /// Translate the incoming buffer and range into an outgoing buffer and range
    /// </summary>
    public byte[] Process(byte[] buffer, ref int offset, ref int length)
    {
        if (_done) return buffer; // feed the rest through without changes
        
        // TODO: handle offset and length being non-standard
        
        
        // If this is the first chunk, look for HTTP stuff-- if we see 'HTTP/', it's probably ok
        if (_first)
        {
            _first = false;
            if (!Contains(buffer, _httpMarker, out _)) // this probably isn't HTTP
            {
                _done = true;
                return buffer;
            }
        }
        
        // Scan for "Host: "
        if ( ! Contains(buffer, _hostMarker, out var start))
        {
            // Not found in this chunk, send as-is
            return buffer;
        }
        
        // We found "Host: ", now find the line end
        var bufferEnd = buffer.Length - 1;
        var end = start + 6;
        while (end < buffer.Length)
        {
            if (buffer[end] == 0x0D)
            {
                if (end < bufferEnd && buffer[end + 1] == 0x0A) // correct end
                {
                    end += 1;
                }
                break;
            }
            if (buffer[end] == 0x0A) // degenerate end
            {
                break;
            }
            end++;
        }

        // Copy up to this point, replace.
        var bufx = new List<byte>();
        bufx.AddRange(buffer.Take(start));
        bufx.AddRange(_realHost);
        bufx.AddRange(buffer.Skip(end+1));
        
        _done = true;
        offset=0;
        length = bufx.Count;
        return bufx.ToArray();
        
        // TODO: Now check that it is prepended by a new-line, and find the next newline after it.
        // NOTE: this doesn't support when the header line is split between fragments. TODO: fix this.

        

    }

    public static bool Contains(byte[] haystack, byte[] needle, out int position)
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