using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol.Payloads;

public class PayloadKeyExchange : MessagePayload
{
    public override PayloadType Type { get => PayloadType.KE; set { } }
    
    public override int Size => HeaderSize + KeyData.Length + 4;

    public byte[] KeyData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// https://www.omnisecu.com/tcpip/what-is-diffie-hellman-group.php
    /// </summary>
    public DhId DiffieHellmanGroup { get; set; }
    
    public PayloadKeyExchange(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public PayloadKeyExchange(DhId diffieHellmanGroup, byte[] publicKey)
    {
        DiffieHellmanGroup = diffieHellmanGroup;
        KeyData = publicKey;
    }

    /// <summary>
    /// Re-write 'Data' array
    /// </summary>
    protected override void Serialise()
    {
        var length = KeyData.Length + 4;
        Data = new byte[length];
        
        var idx = 0;
        Bit.WriteUInt16((ushort)DiffieHellmanGroup, Data, ref idx);
        Data[idx++] = 0; // pad
        Data[idx++] = 0; // pad

        for (int i = 0; i < KeyData.Length; i++)
        {
            Data[idx++] = KeyData[i];
        }
    }
    
    /// <summary>
    /// Read 'Data' array into our specific values
    /// </summary>
    protected override void Deserialise()
    {
        var idx = 0;
        DiffieHellmanGroup = (DhId)Bit.ReadUInt16(Data, ref idx);
        idx += 2; // pad
        
        KeyData = new byte[Data.Length - 4];
        for (int i = 0; i < KeyData.Length; i++)
        {
            KeyData[i] = Data[idx++];
        }
    }

    public override string Describe()
    {
        return $"Payload=KeyExchange; Group={DiffieHellmanGroup.ToString()}; Data={Bit.HexString(KeyData)}";
    }
}