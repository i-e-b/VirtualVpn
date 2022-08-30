using System.Diagnostics.CodeAnalysis;
using VirtualVpn.Enums;

namespace VirtualVpn.EspProtocol.Payloads.PayloadSubunits;

[SuppressMessage("ReSharper", "UnusedMember.Global")]
public class Transform
{
    /// <summary>
    /// Declared length of transform data and headers.
    /// This is read from incoming raw data.
    /// For serialisation see <see cref="Size"/>
    /// </summary>
    public ushort Length { get; set; }
    
    /// <summary>
    /// Transform type
    /// </summary>
    public TransformType Type { get; set; }
    
    /// <summary>
    /// This can be a whole load of different enum types, depending
    /// on context. You will have to cast.
    /// </summary>
    public uint Id { get; set; }
    
    /// <summary>
    /// Attributes of the transform, may be empty.
    /// </summary>
    public List<TransformAttribute> Attributes { get; } = new();
    
    /// <summary>
    /// Calculated size of transform data and headers.
    /// This is used for serialisation.
    /// For declared size, see <see cref="Length"/>
    /// </summary>
    public int Size => Attributes.Sum(a=>a.Size);

    /// <summary>
    /// Human readable description of this transform
    /// </summary>
    public string Description => ToString();

    public byte[] SerialiseAttributes()
    {
        var data = new byte[Size];

        var idx = 0;
        foreach (var attribute in Attributes)
        {
            attribute.WriteBytes(data, ref idx);
        }
        
        if (idx != data.Length) throw new Exception($"Attributes did not fill data. Expected {data.Length}, got {idx}");
        
        return data;
    }

    public override string ToString()
    {
        var idStr = Type switch
        {
            TransformType.ENCR => ((EncryptionTypeId)Id).ToString(),
            TransformType.PRF => ((PrfId)Id).ToString(),
            TransformType.INTEG => ((IntegId)Id).ToString(),
            TransformType.DH => ((DhId)Id).ToString(),
            TransformType.ESN => ((EsnId)Id).ToString(),
            _ => "???"
        };
        
        var subTypeName = Type switch
        {
            TransformType.ENCR => "EncryptionTypeId",
            TransformType.PRF => "PrfId",
            TransformType.INTEG => "IntegId",
            TransformType.DH => "DhId",
            TransformType.ESN => "EsnId",
            _ => "???"
        };

        return $"{Type.ToString()} id={subTypeName}.{idStr} attr=[{string.Join("; ", Attributes.Select(a=>a.ToString()))}]";
    }
}