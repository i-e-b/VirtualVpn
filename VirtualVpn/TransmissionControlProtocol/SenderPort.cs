using VirtualVpn.Helpers;

namespace VirtualVpn.TransmissionControlProtocol;

/// <summary>
/// Combine remote address and local port into a hashable key
/// </summary>
public readonly struct SenderPort
{
    /// <summary>
    /// Address of the remote system as an internal representation.
    /// If zero, this is invalid.
    /// </summary>
    public readonly ulong SenderAddress;
    
    /// <summary>
    /// Port on local system being requested.
    /// If zero, this is invalid.
    /// </summary>
    public readonly ushort DestinationPort;

    public SenderPort(byte[] senderAddress, int destinationPort)
    {
        SenderAddress = Bit.BytesToUInt64Msb(senderAddress);
        DestinationPort = (ushort)destinationPort;
    }

    public override int GetHashCode()
    {
        int h = DestinationPort + (DestinationPort << 16);
        h ^= (int)(SenderAddress >>  0);
        h ^= (int)(SenderAddress >> 32);
        return h;
    }
}