namespace RawSocketTest.Payloads;

public class Transform
{
    public ushort Length { get; set; }
    public TransformType Type { get; set; }
    
    /// <summary>
    /// This can be a whole load of different enum types, depending
    /// on context. You will have to cast.
    /// </summary>
    public uint Id { get; set; }
    public List<Attribute> Attributes { get; set; } = new();
}