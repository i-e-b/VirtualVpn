using RawSocketTest.Helpers;
using RawSocketTest.Payloads.PayloadSubunits;

namespace RawSocketTest.Payloads;

/// <summary>
/// Base class. Use Tsi or Tsr
/// </summary>
public class PayloadTsx : MessagePayload
{
    public override int Size => HeaderSize + SelectorSize + 4;
    public int SelectorSize => Selectors.Sum(s=>s.Size);

    public int SelectorCount { get; set; }
    public readonly List<TrafficSelector> Selectors = new();

    protected PayloadTsx(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    protected override void Serialise()
    {
        SelectorCount = Selectors.Count;
        
        var idx = 0;
        Data = new byte[Size - HeaderSize];
        
        Data[idx++] = (byte)SelectorCount;
        idx += 3; // unused
        
        foreach (var selector in Selectors)
        {
             selector.WriteBytes(Data, ref idx);
        }
    }
    
    protected override void Deserialise()
    {
        var idx = 0;
        
        SelectorCount = Data[idx++];
        idx+=3; // unused

        while (idx < Data.Length && Selectors.Count < SelectorCount)
        {
            Selectors.Add(TrafficSelector.Parse(Data, ref idx));
        }

        if (Selectors.Count != SelectorCount)
        {
            Log.Warn($"    WARNING: Unexpected traffic selector size. Expected {SelectorCount}, but got {Selectors.Count}");
        }
    }

    public override string Describe()
    {
        return $"Payload={Type.ToString()}; Selectors=[{string.Join(" | ", Selectors.Select(s=>s.Describe()))}];";
    }
}

public class PayloadTsr : PayloadTsx
{
    // pvpn/message.py:450
    public override PayloadType Type { get => PayloadType.TSr; set { } }
    public PayloadTsr(byte[] data, ref int idx, ref PayloadType nextPayload):base(data,ref idx, ref nextPayload) { }
}
public class PayloadTsi : PayloadTsx
{
    // pvpn/message.py:435
    public override PayloadType Type { get => PayloadType.TSi; set { } }
    public PayloadTsi(byte[] data, ref int idx, ref PayloadType nextPayload):base(data,ref idx, ref nextPayload) { }
}