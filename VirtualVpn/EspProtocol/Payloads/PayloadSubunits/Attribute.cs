using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol.Payloads.PayloadSubunits;

public class TransformAttribute
{
    private const int KeyValueFlag = 0x8000;
    
    public TransformAttribute() { }

    public TransformAttribute(TransformAttr type, ushort value)
    {
        Type = type;
        Value = value;
    }
    
    public TransformAttribute(TransformAttr type, byte[] valueBytes)
    {
        Type = type;
        Value = (ushort)valueBytes.Length;
        ValueBytes = valueBytes;
    }

    public void WriteBytes(byte[] data, ref int idx)
    {
        if (ValueBytes.Length > 0)
        {
            var length = ValueBytes.Length;
            Bit.WriteUInt16((ushort)Type, data, ref idx);
            Bit.WriteUInt16((ushort)length, data, ref idx);
            for (int i = 0; i < length; i++)
            {
                data[idx++] = ValueBytes[i];
            }
        }
        else
        {
            Bit.WriteUInt16((ushort)((int)Type | KeyValueFlag), data, ref idx);
            Bit.WriteUInt16(Value, data, ref idx);
        }
    }
    
    public static IEnumerable<TransformAttribute> ParseChain(byte[] data, int length, ref int idx)
    {
        var result = new List<TransformAttribute>();
        if (length + idx > data.Length) return result; // truncated data or corrupted length
        
        var remains = length;
        while (remains > 0)
        {
            var attr = new TransformAttribute();
            var type = Bit.ReadUInt16(data, ref idx);
            var value = Bit.ReadUInt16(data, ref idx);
            remains -= 4;

            if ((type & KeyValueFlag) != 0) // bit flag marks this as a key-value pair
            {
                attr.Type = (TransformAttr)(type & 0x7fff);
                attr.Value = value;
            }
            else // no flag, so 'value' is the length of a byte array
            {
                attr.Type = (TransformAttr)type;
                attr.Value = value;
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

    public byte[] ValueBytes { get; private set; } = Array.Empty<byte>();
    public ushort Value { get; set; }
    public TransformAttr Type { get; set; }

    public override string ToString()
    {
        return $"{Type.ToString()}: {Value}";
    }
}