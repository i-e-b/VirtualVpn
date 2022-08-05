namespace RawSocketTest.Payloads;

public class Proposal
{
    public byte Number { get; set; }

    public IkeProtocolType Protocol { get; set; }

    public byte SpiSize { get; set; }
    public byte[] SpiData { get; set; } = Array.Empty<byte>();

    public byte TransformCount { get; set; }
    public List<Transform> Transforms { get; set; } = new();
    
    public int Size => 4 + SpiData.Length + Transforms.Sum(t=>t.Size) + Transforms.Count * 8;

    public static Proposal Parse(byte[] data, ushort length, ref int idx)
    {
        var result = new Proposal();
        
        if (length + idx >= data.Length) return result; // truncated data or corrupted length
        
        // read proposal header
        result.Number = data[idx++];
        result.Protocol = (IkeProtocolType)data[idx++];
        result.SpiSize = data[idx++];
        result.TransformCount = data[idx++];
        
        // read SPI bytes
        result.SpiData = new byte[result.SpiSize];
        for (int i = 0; i < result.SpiSize; i++)
        {
            result.SpiData[i] = data[idx++];
        }
        
        // each proposal has a chain of Transforms
        byte more = 1;
        var end = length + idx - 8;
        while (more > 0 && idx < end)
        {
            more = data[idx++];
            var trans = new Transform();
            idx++;// pad
            trans.Length = Bit.ReadUInt16(data, ref idx);
            trans.Type = (TransformType)data[idx++];
            idx++;// pad
            trans.Id = Bit.ReadUInt16(data, ref idx);
            
            // pvpn/message.py:256
            trans.Attributes.AddRange(Attribute.ParseChain(data, trans.Length - 8, ref idx));
            
            result.Transforms.Add(trans);
        }

        return result;
    }

    public Transform? GetTransform(TransformType type) => Transforms.FirstOrDefault(t=>t.Type == type);
}