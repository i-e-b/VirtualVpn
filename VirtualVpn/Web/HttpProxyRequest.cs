
namespace VirtualVpn.Web;

/// <summary>
/// Wrapper for a remote machine to make a HTTP call
/// as if it were in the VirtualVPN encryption domain.
/// </summary>
public class HttpProxyRequest
{
    /// <summary>
    /// IP address of server at the far side of the VPN tunnel
    /// that we are trying to contact.
    /// </summary>
    public string TargetMachineIp { get; set; } = "";
    
    /// <summary>
    /// HTTP request headers (must be complete and correct)
    /// </summary>
    public IDictionary<string,string> Headers { get; set; } = new Dictionary<string, string>();
    
    /// <summary>
    /// HTTP request method (e.g. POST, GET, etc)
    /// </summary>
    public string HttpMethod { get; set; } = "GET";
    
    /// <summary>
    /// HTTP body (or null)
    /// </summary>
    public byte[]? Body { get; set; }
    
    /// <summary>
    /// HTTP request Url
    /// </summary>
    public string Url { get; set; } = "";
    
    /// <summary>
    /// Port on the remote server we will query
    /// </summary>
    public int Port { get; set; } = 80;
    
    /// <summary>
    /// Address in the VirtualVPN range that we will pretend to be
    /// </summary>
    public string ProxyLocalAddress { get; set; } = "";
}