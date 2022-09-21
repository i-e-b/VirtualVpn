using System.Globalization;
using System.Net;
using VirtualVpn.Helpers;

namespace VirtualVpn.InternetProtocol;

/// <summary>
/// Serialisation definition for IPv4 address
/// </summary>
[ByteLayout]
public class IpV4Address: IEquatable<IpV4Address>
{
    [ByteString(bytes:4, order:0)]
    public readonly byte[] Value = Array.Empty<byte>();

    public IpV4Address() { }
    public IpV4Address(byte[] address) { Value = address; }

    public string AsString => ToString();
    public bool IsLocalhost => Value.Length == 4 && Value[0] == 127 && Value[1] == 0 && Value[2] == 0 && Value[3] == 1;
    
    /// <summary>
    /// IP address of the local loop-back interface
    /// </summary>
    public static IpV4Address Localhost => new(new byte[] { 127, 0, 0, 1 });
    
    /// <summary>
    /// IP address for unspecified location.
    /// Can mean 'any' or 'none' depending on context.
    /// </summary>
    public static IpV4Address Any => new(new byte[] { 0, 0, 0, 0 });

    public uint AsInt => Bit.BytesToUInt32(Value);

    public override string ToString()
    {
        if (Value.Length < 4) return "<empty>";
        return $"{Value[0]}.{Value[1]}.{Value[2]}.{Value[3]}";
    }

    /// <summary>
    /// Create a copy of this address
    /// </summary>
    public IpV4Address Copy()
    {
        return new IpV4Address(new byte[4])
        {
            Value = {
                [0] = Value[0],
                [1] = Value[1],
                [2] = Value[2],
                [3] = Value[3]
            }
        };
    }

    public static IpV4Address FromString(string addressString)
    {
        var bits = addressString.Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (bits.Length != 4) throw new Exception($"Could not parse '{addressString}' as an IPv4 address");
        
        var bytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            var ok = byte.TryParse(bits[i], NumberStyles.Integer, null, out var b);
            if (!ok)
            {
                throw new Exception($"Could not parse '{bits[i]}' as decimal byte value");
            }
            bytes[i] = b;
        }
        return new IpV4Address(bytes);
    }

    public static IpV4Address FromEndpoint(IPEndPoint endPoint)
    {
        return new IpV4Address(endPoint.Address.GetAddressBytes());
    }

    public override bool Equals(object? obj)
    {
        if (obj is not IpV4Address other) return false;
        
        for (int i = 0; i < 4; i++)
        {
            if (Value[i] != other.Value[i]) return false;
        }
        
        return true;
    }

    public bool Equals(IpV4Address? other)
    {
        if (other is null) return false;
        
        for (int i = 0; i < 4; i++)
        {
            if (Value[i] != other.Value[i]) return false;
        }
        
        return true;
    }

    public override int GetHashCode()
    {
        return Value.GetHashCode();
    }
    
    public static bool operator ==(IpV4Address left, IpV4Address right) => left.Equals(right);

    public static bool operator !=(IpV4Address left, IpV4Address right) => !(left == right);

    public IPEndPoint MakeEndpoint(int port) => new(ToIpAddress(), port);

    public IPAddress ToIpAddress() => new(Value);

    public static string Describe(byte[] bytes)
    {
        if (bytes.Length < 4) return "<empty>";
        return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.{bytes[3]}";
    }
}