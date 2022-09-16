namespace VirtualVpn.Web;

public class ProxyRequest
{
    public IDictionary<string,string> Headers { get; set; } = new Dictionary<string, string>();
    public string HttpMethod { get; set; } = "GET";
    public byte[]? Body { get; set; }
}

public class ProxyResponse
{
    public IDictionary<string,string> Headers { get; set; } = new Dictionary<string, string>();
    public int StatusCode { get; set; }
    public string StatusDescription { get; set; } = "";
    public byte[]? Body { get; set; }
}