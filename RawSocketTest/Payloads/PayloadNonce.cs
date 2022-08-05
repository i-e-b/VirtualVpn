namespace RawSocketTest.Payloads;

public class PayloadNonce : MessagePayload
{
    public override PayloadType Type { get => PayloadType.NONCE; set { } }

    public byte[] RandomData => Data;

    public PayloadNonce(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public PayloadNonce(byte[] nonce)
    {
        throw new NotImplementedException();
    }

    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
    }
}