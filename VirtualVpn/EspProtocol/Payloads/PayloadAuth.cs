using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol.Payloads;

public class PayloadAuth : MessagePayload
{
    public override PayloadType Type { get => PayloadType.AUTH; set { } }
    
    public override int Size => HeaderSize + AuthData.Length + 4;

    public AuthMethod AuthMethod { get; set; }
    public byte[] AuthData { get; set; } = Array.Empty<byte>();

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
        var idx = 0;
        Data = new byte[AuthData.Length + 4];
        
        Data[idx++] = (byte)AuthMethod;
        idx += 3; // unused
        
        Bit.CopyOver(AuthData, Data, ref idx);
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