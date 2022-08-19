using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;

namespace VirtualVpn.TransmissionControlProtocol;

/// <summary>
/// Low Level network endpoint
/// <p></p>
/// https://github.com/los93sol/RawSocketSample/tree/master/RawSocketSample
/// </summary>
public class LowLevelEndPoint : EndPoint
{
    private readonly NetworkInterface _networkInterface;

    public LowLevelEndPoint(NetworkInterface networkInterface)
    {
        _networkInterface = networkInterface;
    }

    public override SocketAddress Serialize()
    {
        // Based on sockaddr_ll, check linux/if_packet.h for more information
        var socketAddress = new SocketAddress(AddressFamily.Packet, 20);

        var indexProperty = _networkInterface.GetType().GetProperty("Index", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        var nicIndex = (int)(indexProperty?.GetValue(_networkInterface) ?? 0);
        var asBytes = BitConverter.GetBytes(nicIndex);

        socketAddress[4] = asBytes[0];
        socketAddress[5] = asBytes[1];
        socketAddress[6] = asBytes[2];
        socketAddress[7] = asBytes[3];

        if (_networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
        {
            var ethPAll = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)3));   // ETH_P_ALL
            socketAddress[2] = ethPAll[0];
            socketAddress[3] = ethPAll[1];
            //socketAddress[10] = 4;  // PACKET_OUTGOING
        }
        return socketAddress;
    }

    public static LowLevelEndPoint GetFirstLoopback() => new(GetFirstLoopbackInterface());

    /// <summary>
    /// Find first loopback device
    /// </summary>
    /// <returns></returns>
    public static NetworkInterface GetFirstLoopbackInterface()
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var networkInterface in interfaces)
        {
            if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback) return networkInterface;
        }
        
        throw new Exception($"Could not find a loopback device ({interfaces.Length} devices found)");
    }
}