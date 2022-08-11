using RawSocketTest.Helpers;

namespace RawSocketTest.Payloads.PayloadSubunits;

public class TrafficSelector
{
    // pvpn/message.py:402
    
    public TrafficSelectType Type { get; set; }
    public IpProtocol Protocol { get; set; }
    public int StartPort { get; set; }
    public int EndPort { get; set; }
    public byte[] StartAddress { get; set; } = Array.Empty<byte>();
    public byte[] EndAddress { get; set; } = Array.Empty<byte>();
    
    
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

    /// <summary>
    /// Declared length from deserialisation
    /// </summary>
    public ushort Length { get; set; }

    public string Describe()
    {
        if (StartAddress.Length == 4)
        {
            return $"Type={Type.ToString()}, Pr={Protocol.ToString()}, Port={StartPort}-{EndPort}, " +
                   $"Address={StartAddress[0]}.{StartAddress[1]}.{StartAddress[2]}.{StartAddress[2]} - {EndAddress[0]}.{EndAddress[1]}.{EndAddress[2]}.{EndAddress[3]}";
        }
        
        return $"Type={Type.ToString()}, Pr={Protocol.ToString()}, Port={StartPort}-{EndPort}, " +
               $"Address={Bit.HexString(StartAddress)} - {Bit.HexString(EndAddress)}";
    }
}