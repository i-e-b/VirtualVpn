using RawSocketTest.Helpers;

namespace RawSocketTest.Payloads;

public class PayloadDelete : MessagePayload
{
    public override PayloadType Type { get => PayloadType.DELETE; set { } }

    public override int Size => HeaderSize + SpiList.Sum(i => i.Length) + 4;

    public List<byte[]> SpiList { get; set; } = new();
    public IkeProtocolType ProtocolType { get; set; }
    public int SpiSize { get; set; }

    public PayloadDelete(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public PayloadDelete(IkeProtocolType protocol, IEnumerable<byte[]> matches)
    {
         SpiList.AddRange(matches);
         SpiSize = SpiList.FirstOrDefault()?.Length ?? 0;
         ProtocolType = protocol;
    }

    protected override void Serialise()
    {
        SpiSize = SpiList.FirstOrDefault()?.Length ?? 0;
        
        Data = new byte[SpiList.Sum(i => i.Length) + 4];
        
        var idx = 0;
        Data[idx++] = (byte)ProtocolType;
        Data[idx++] = (byte)SpiSize;
        foreach (var spi in SpiList)
        {
            Bit.CopyOver(spi, Data, ref idx);
        }
    }
    
    protected override void Deserialise()
    {
        var idx = 0;
        
        ProtocolType = (IkeProtocolType)Data[idx++];
        SpiSize = Data[idx++];
        var count = Bit.ReadUInt16(Data, ref idx);

        while (count > 0 && idx < Data.Length)
        {
            SpiList.Add(Bit.Subset(SpiSize, Data, ref idx));
        }
    }


    public override string Describe()
    {
        return $"Payload=Delete; Protocol={ProtocolType.ToString()}; SpiCount={SpiList.Count}";
    }
}