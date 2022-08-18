using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.Payloads;

public class PayloadCp : MessagePayload
{
    public override PayloadType Type { get => PayloadType.CP; set { } }
    
    public override int Size => HeaderSize + Data.Length;

    public PayloadCp(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
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