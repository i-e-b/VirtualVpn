using VirtualVpn.Helpers;

namespace VirtualVpn.InternetProtocol;

/// <summary>
/// Serialisation definition for IPv4 address
/// </summary>
[ByteLayout]
public class IpV4Address
{
    [ByteString(bytes:4, order:0)]
    public byte[] Value = Array.Empty<byte>();

    public IpV4Address() { }
    public IpV4Address(byte[] address) { Value = address; }

    public string AsString => ToString();
    public bool IsLocalhost => Value.Length == 4 && Value[0] == 127 && Value[1] == 0 && Value[2] == 0 && Value[3] == 1;
    
    /// <summary>
    /// IP address of the local loop-back interface
    /// </summary>
    public static IpV4Address Localhost => new() { Value = new byte[]{127,0,0,1}};
    
    /// <summary>
    /// IP address for unspecified location.
    /// Can mean 'any' or 'none' depending on context.
    /// </summary>
    public static IpV4Address Any => new() { Value = new byte[]{0,0,0,0}};

    public override string ToString()
    {
        if (Value.Length < 4) return "<empty>";
        return $"{Value[0]}.{Value[1]}.{Value[2]}.{Value[3]}";
    }
}