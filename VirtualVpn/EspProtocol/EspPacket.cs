using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol;

[ByteLayout]
public class EspPacket
{
    [BigEndian(bytes: 4, order: 0)]
    public uint Spi;
    
    [BigEndian(bytes: 4, order: 1)]
    public uint Sequence;
    
    [RemainingBytes(order: 3)]
    public byte[] Payload = Array.Empty<byte>();
}