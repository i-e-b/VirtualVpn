using RawSocketTest.Crypto;

namespace RawSocketTest.Payloads;

public class PayloadSecured : MessagePayload
{
    public override PayloadType Type { get => PayloadType.SK; set { } }
    
    public override int Size => HeaderSize + Data.Length;

    public byte[]? PlainBody { get; private set; }

    public PayloadSecured(byte[] data, IkeCrypto? ikeCrypto, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
        
        if (ikeCrypto is null) return; // can't decrypt
        
        var ok = ikeCrypto.VerifyChecksum(Data);
        if (!ok) return;
        
        PlainBody = ikeCrypto.Decrypt(Data, out _);
    }
    
    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
    }
}