using VirtualVpn.Enums;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;

namespace VirtualVpn.EspProtocol.Payloads.PayloadSubunits;

/// <summary>
/// Class for saving settings, to be used with <see cref="TrafficSelector"/>
/// </summary>
public class TrafficSelectorSetting
{
    public ushort StartPort { get; set; }
    public ushort EndPort { get; set; } = 65535;
    public string StartAddress { get; set; } = "";
    public string EndAddress { get; set; } = "";

    public TrafficSelector ToSelector()
    {
        return new TrafficSelector
        {
            Type = TrafficSelectType.TS_IPV4_ADDR_RANGE,
            Protocol = IpProtocol.ANY,
            StartPort = StartPort,
            EndPort = EndPort,
            StartAddress = IpV4Address.FromString(StartAddress).Value,
            EndAddress = IpV4Address.FromString(EndAddress).Value,
        };
    }
}

/// <summary>
/// Class for IKEv2 payloads
/// </summary>
public class TrafficSelector
{
    // pvpn/message.py:402
    
    public TrafficSelectType Type { get; set; }
    public IpProtocol Protocol { get; set; }
    public ushort StartPort { get; set; }
    public ushort EndPort { get; set; }
    public byte[] StartAddress { get; set; } = Array.Empty<byte>();
    public byte[] EndAddress { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Declared length from deserialisation
    /// </summary>
    public ushort Length { get; set; }

    public int Size => AddrSize * 2 + 8;
    public int AddrSize => StartAddress.Length;
    
    public void WriteBytes(byte[] data, ref int idx)
    {
        Length = (ushort)Size;
        
        data[idx++] = (byte)Type;
        data[idx++] = (byte)Protocol;
        
        Bit.WriteUInt16(Length, data, ref idx);
        Bit.WriteUInt16(StartPort, data, ref idx);
        Bit.WriteUInt16(EndPort, data, ref idx);
        
        Bit.CopyOver(StartAddress, data, ref idx);
        Bit.CopyOver(EndAddress, data, ref idx);
    }
    
    public static TrafficSelector Parse(byte[] data, ref int idx)
    {
        // pvpn/message.py:421
        var result = new TrafficSelector
        {
            Type = (TrafficSelectType)data[idx++],
            Protocol = (IpProtocol)data[idx++],
            Length = Bit.ReadUInt16(data, ref idx),
            StartPort = Bit.ReadUInt16(data, ref idx),
            EndPort = Bit.ReadUInt16(data, ref idx)
        };

        var addrLen = (result.Length - 8) / 2;
        result.StartAddress = Bit.Subset(addrLen, data, ref idx);
        result.EndAddress = Bit.Subset(addrLen, data, ref idx);
        
        return result;
    }

    public string Describe()
    {
        if (StartAddress.Length == 4)
        {
            return $"Type={Type.ToString()}, Pr={Protocol.ToString()}, Port={StartPort}-{EndPort}, " +
                   $"Address={StartAddress[0]}.{StartAddress[1]}.{StartAddress[2]}.{StartAddress[3]} - {EndAddress[0]}.{EndAddress[1]}.{EndAddress[2]}.{EndAddress[3]}";
        }
        
        return $"Type={Type.ToString()}, Pr={Protocol.ToString()}, Port={StartPort}-{EndPort}, " +
               $"Address={Bit.HexString(StartAddress)} - {Bit.HexString(EndAddress)}";
    }

    public bool Contains(IpV4Address target)
    {
        var low = new IpV4Address(StartAddress).AsInt;
        var mid = target.AsInt;
        var high = new IpV4Address(EndAddress).AsInt;
        
        Log.Trace($"    IPv4: {low} .. {mid} .. {high}");
        
        return (mid >= low) && (mid <= high);
    }
}