using RawSocketTest.Helpers;

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

    private const byte TransformHasMore = 3;
    private const byte TransformLastOne = 0;

    public byte[] Serialise()
    {
        var data = new byte[Size];
        
        // update sizes
        SpiSize = (byte)SpiData.Length;
        TransformCount = (byte)Transforms.Count;
        
        var idx = 0;
        data[idx++] = Number;
        data[idx++] = (byte)Protocol;
        data[idx++] = SpiSize;
        data[idx++] = TransformCount;

        for (int i = 0; i < SpiData.Length; i++)
        {
            data[idx++] = SpiData[i];
        }

        for (int i = 0; i < Transforms.Count; i++)
        {
            var more = (i == TransformCount - 1) ? TransformLastOne : TransformHasMore; // this is NOT a count, it's a flag, which is different from other 'more' flags
            var transform = Transforms[i];
            var attrData = transform.SerialiseAttributes();
            transform.Length = (ushort)(attrData.Length+8); // data is without chain headers
            
            
            data[idx++] = (byte)more;
            idx++; // pad
            Bit.WriteUInt16(transform.Length, data, ref idx);
            data[idx++] = (byte)transform.Type;
            idx++; // pad
            Bit.WriteUInt16((ushort)transform.Id, data, ref idx); // data is without chain headers

            for (int k = 0; k < attrData.Length; k++)
            {
                data[idx++] = attrData[k];
            }
        }
        
        return data;
    }
    
    public static Proposal Parse(byte[] data, ushort length, ref int idx)
    {
        var result = new Proposal();
        
        if (length + idx > data.Length) return result; // truncated data or corrupted length
        
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
            trans.Attributes.AddRange(TransformAttribute.ParseChain(data, trans.Length - 8, ref idx));
            
            result.Transforms.Add(trans);
        }

        return result;
    }

    public Transform? GetTransform(TransformType type) => Transforms.FirstOrDefault(t=>t.Type == type);
}