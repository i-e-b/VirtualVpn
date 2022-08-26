using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol.Payloads;

public class PayloadNonce : MessagePayload
{
    public override PayloadType Type { get => PayloadType.NONCE; set { } }
    
    public override int Size => HeaderSize + Data.Length;

    public PayloadNonce(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public PayloadNonce(byte[] nonce)
    {
        Data = nonce;
    }

    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
    }

    public override string Describe()
    {
        return $"Payload=N-once; Data={Bit.HexString(Data)}";
    }
}