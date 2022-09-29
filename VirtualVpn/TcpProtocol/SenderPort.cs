using VirtualVpn.InternetProtocol;

namespace VirtualVpn.TcpProtocol;

/// <summary>
/// Combine remote address and local port into a hashable key
/// </summary>
public class SenderPort
{
    /// <summary>
    /// Address of the remote system as an internal representation.
    /// If zero, this is invalid.
    /// </summary>
    public IpV4Address Address { get; }

    /// <summary>
    /// Port on local system being requested.
    /// If zero, this is invalid.
    /// </summary>
    public readonly ushort Port;

    public override bool Equals(object? obj)
    {
        if (obj is SenderPort other)
        {
            return Port    == other.Port
                && Address == other.Address;
        }
        return false;
    }

    public SenderPort(byte[] senderAddress, int destinationPort)
    {
        Address = new IpV4Address(senderAddress);
        if (Address.IsZero())
        {
            Log.Critical("Tried to use a zero-value address as a key");
            throw new Exception("Tried to use a zero-value address as a key");
        }

        Port = (ushort)destinationPort;
    }

    public override int GetHashCode()
    {
        var addr = (int)Address.AsInt;
        var h = Port + (Port << 16);
        h ^= addr;
        return h;
    }

    public static bool operator ==(SenderPort left, SenderPort right) => left.Equals(right);

    public static bool operator !=(SenderPort left, SenderPort right) => !(left == right);

    public string Describe()
    {
        return $"{Address.AsString}:{Port}";
    }
}