namespace VirtualVpn.Web;

/// <summary>
/// Http response from <see cref="HttpProxyRequest"/>
/// </summary>
public class HttpProxyResponse
{
    public IDictionary<string,string> Headers { get; set; } = new Dictionary<string, string>();
    public int StatusCode { get; set; }
    public string StatusDescription { get; set; } = "";
    public byte[]? Body { get; set; }

    /// <summary>
    /// True if the proxy request was completed.
    /// This can be true even if the StatusCode is an error code.
    /// </summary>
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
}