namespace RawSocketTest.Payloads;

/// <summary>
/// Payload for messages we don't understand
/// </summary>
public class PayloadUnknown : MessagePayload
{
    public PayloadUnknown(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public override int Size => HeaderSize + Data.Length;
    
    protected override void Serialise()
    {
    }

    protected override void Deserialise()
    {
    }

    public override string Describe()
    {
        return "Unknown payload type";
    }
}