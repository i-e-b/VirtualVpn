namespace RawSocketTest.Payloads;

public class Attribute
{
    public static List<Attribute> ParseChain(byte[] data, int length, ref int idx)
    {
        var result = new List<Attribute>();
        if (length + idx >= data.Length) return result; // truncated data or corrupted length
        
        var remains = length;
        while (remains > 0)
        {
            var attr = new Attribute();
            var type = Bit.ReadUInt16(data, ref idx);
            var value = Bit.ReadUInt16(data, ref idx);
            remains -= 4;

            if ((type & 0x8000) != 0) // bit flag marks this as a key-value pair
            {
                attr.Type = (TransformAttr)(type & 0x7fff);
                attr.Value = value;
            }
            else // no flag, so 'value' is the length of a byte array
            {
                attr.Type = (TransformAttr)type;
                remains -= value;
                attr.ValueBytes = new byte[value];
                for (int i = 0; i < value; i++)
                {
                    attr.ValueBytes[i] = data[idx++];
                }
            }
            
            result.Add(attr);
        }


        return result;
    }

    /// <summary>
    /// Size required to store this attribute
    /// </summary>
    public int Size => 4 + ValueBytes.Length;

    public byte[] ValueBytes { get; set; } = Array.Empty<byte>();
    public ushort Value { get; set; }
    public TransformAttr Type { get; set; }
}