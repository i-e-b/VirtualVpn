
using System.Diagnostics.CodeAnalysis;

namespace VirtualVpn.Web;

/// <summary>
/// Wrapper for a remote machine to make a HTTP call
/// as if it were in the VirtualVPN encryption domain.
/// </summary>
[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
[SuppressMessage("ReSharper", "PropertyCanBeMadeInitOnly.Global")]
public class HttpProxyRequest
{
    /// <summary>
    /// HTTP request Url.
    /// <p></p>
    /// MUST include scheme and host (i.e. https://192.168.0.40 )<br/>
    /// SHOULD include port and path (i.e. :443/my/path)
    /// </summary>
    public string Url { get; set; } = "";
    
    /// <summary>
    /// HTTP request method (e.g. "POST", "GET", "PUT", etc)
    /// </summary>
    public string HttpMethod { get; set; } = "GET";
    
    /// <summary>
    /// HTTP request headers (must be complete and correct)
    /// </summary>
    public IDictionary<string,string> Headers { get; set; } = new Dictionary<string, string>();
    
    /// <summary>
    /// HTTP body to send (or null).
    /// Should only be included in PUT/POST calls
    /// </summary>
    public byte[]? Body { get; set; }
    
    /// <summary>
    /// Single address in the VirtualVPN range that this call will pretend to come from.
    /// <p></p>
    /// MUST be formatted as a dotted ip v4 string (e.g. "55.55.50.10")
    /// </summary>
    public string ProxyLocalAddress { get; set; } = "";
}