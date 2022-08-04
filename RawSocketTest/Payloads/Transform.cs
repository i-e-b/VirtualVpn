namespace RawSocketTest.Payloads;

public class Transform
{
    public ushort Length { get; set; }
    public TransformType Type { get; set; }
    
    /// <summary>
    /// This can be <see cref="EncryptionTypeId"/> or <see cref="DhId"/> depending on context
    /// </summary>
    public uint Id { get; set; }
    public List<Attribute> Attributes { get; set; } = new();
}