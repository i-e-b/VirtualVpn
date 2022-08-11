using RawSocketTest.Helpers;

namespace RawSocketTest.Payloads;

public class PayloadAuth : MessagePayload
{
    public override PayloadType Type { get => PayloadType.AUTH; set { } }
    
    public override int Size => HeaderSize + Data.Length;

    public AuthMethod AuthMethod { get; set; }
    public byte[] AuthData { get; set; }

    public PayloadAuth(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public PayloadAuth(AuthMethod authMethod, byte[] authData)
    {
        AuthMethod = authMethod;
        AuthData = authData;
    }

    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
        var idx = 0;
        AuthMethod = (AuthMethod)Data[idx++];
        idx += 3; // unused
        
        AuthData = Bit.Subset(-1, Data, ref idx);
    }

    public override string Describe() => $"Payload=AUTH (39); Method={AuthMethod.ToString()}; Data={Bit.HexString(AuthData)}";
}