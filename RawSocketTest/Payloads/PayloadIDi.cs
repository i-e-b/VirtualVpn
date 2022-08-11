using System.Text;
using RawSocketTest.Helpers;

namespace RawSocketTest.Payloads;

// pvpn/message.py:117
public class PayloadIDi : MessagePayload
{
    public override PayloadType Type { get => PayloadType.IDi; set { } }
    
    public override int Size => HeaderSize + Data.Length;

    public PayloadIDi(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        // IDi is inside an SK message.
        // Not sure, but this seems to result in a slightly different structure?
        ReadData(data, ref idx, ref nextPayload);
    }

    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
        var idx = 0;
        IdType = (IdType)Data[idx++];
        Protocol = (IpProtocol)Data[idx++];
        Port = Bit.ReadUInt16(Data, ref idx);
        
        IdData = Bit.Subset(Data.Length-4, Data, ref idx);
    }

    public override string Describe()
    {
        switch (IdType)
        {
            case IdType.ID_IPV4_ADDR:
                return $"Payload=IDi; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Address={IdData[0]}.{IdData[1]}.{IdData[2]}.{IdData[3]}";
                
            case IdType.ID_FQDN:
                return $"Payload=IDi; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Address={Encoding.ASCII.GetString(IdData)}";
                
            case IdType.ID_RFC822_ADDR:
            case IdType.ID_IPV4_ADDR_SUBNET:
            case IdType.ID_IPV6_ADDR:
            case IdType.ID_IPV6_ADDR_SUBNET:
            case IdType.ID_IPV4_ADDR_RANGE:
            case IdType.ID_IPV6_ADDR_RANGE:
            case IdType.ID_DER_ASN1_DN:
            case IdType.ID_DER_ASN1_GN:
            case IdType.ID_KEY_ID:
            case IdType.ID_FC_NAME:
                return $"Payload=IDi; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Data={Bit.HexString(IdData)}";
                
            case IdType.ID_NULL:
                return $"Payload=IDi; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; (null?) Data={Bit.HexString(IdData)}";
                
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    public byte[] IdData { get; set; } = Array.Empty<byte>();

    public ushort Port { get; set; }

    public IpProtocol Protocol { get; set; }

    public IdType IdType { get; set; }
}