using System.Text;
using VirtualVpn.Helpers;

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

    /// <summary>
    /// Output a human-readable summary of this response
    /// </summary>
    public string Describe()
    {
        var sb = new StringBuilder();

        if (Success) sb.AppendLine("Success");
        else sb.AppendLine($"Request failed: {ErrorMessage ?? "<no details>"}");
        
        
        sb.AppendLine($"{StatusCode} {StatusDescription}");

        if (Headers.Count > 0)
        {
            foreach (var header in Headers)
            {
                sb.AppendLine($"{header.Key}: {header.Value}");
            }
        }
        else
        {
            sb.AppendLine("<no headers returned>");
        }

        if (Body is null)
        {
            sb.AppendLine("<no body data>");
        }
        else
        {
            sb.AppendLine();
            sb.Append(Bit.Describe("body", Body));
        }

        return sb.ToString();
    }
}