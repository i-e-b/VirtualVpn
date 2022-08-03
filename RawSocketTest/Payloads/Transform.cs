namespace RawSocketTest.Payloads;

public class Transform
{
    public ushort Length { get; set; }
    public TransformType Type { get; set; }
    public ushort Id { get; set; }
    public List<Attribute> Attributes { get; set; } = new();
}