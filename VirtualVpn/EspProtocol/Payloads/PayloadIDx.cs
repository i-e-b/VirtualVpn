using System.Text;
using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.EspProtocol.Payloads;

/// <summary>
/// Flip side of <see cref="PayloadIDr"/>.
/// </summary>
public class PayloadIDi : PayloadIDx
{
    public override PayloadType Type => PayloadType.IDi;
    
    public PayloadIDi(byte[] data, ref int idx, ref PayloadType nextPayload) : base(data, ref idx, ref nextPayload) { }
    
    public PayloadIDi(IdType type, byte[] idData, int port, IpProtocol protocol)
    {
        // like pvpn/message.py:118
        IdType=type;
        IdData=idData;
        Port = (ushort)port;
        Protocol = protocol;
    }
}

/// <summary>
/// Flip side of <see cref="PayloadIDi"/>.
/// </summary>
public class PayloadIDr: PayloadIDx
{
    public override PayloadType Type => PayloadType.IDr;

    public PayloadIDr(byte[] data, ref int idx, ref PayloadType nextPayload) : base(data, ref idx, ref nextPayload)
    {
    }

    public PayloadIDr(IdType type, byte[] idData, int port, int protocol)
    {
        // like pvpn/message.py:118
        IdType=type;
        IdData=idData;
        Port = (ushort)port;
        Protocol = (IpProtocol)protocol;
    }
    
    public PayloadIDr(IdType type, byte[] idData, int port, IpProtocol protocol)
    {
        // like pvpn/message.py:118
        IdType=type;
        IdData=idData;
        Port = (ushort)port;
        Protocol = protocol;
    }
}

// pvpn/message.py:117
public class PayloadIDx : MessagePayload
{
    public override int Size => HeaderSize + IdData.Length + 4;

    protected PayloadIDx() { }
    
    protected PayloadIDx(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        // IDi is usually inside an SK message.
        ReadData(data, ref idx, ref nextPayload);
    }

    protected override void Serialise()
    {
        Data = new byte[IdData.Length + 4];
        
        var idx = 0;
        Data[idx++] = (byte)IdType;
        Data[idx++] = (byte)Protocol;
        Bit.WriteUInt16(Port, Data, ref idx);

        for (int i = 0; i < IdData.Length; i++)
        {
            Data[idx++] = IdData[i];
        }
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
                return $"Payload=IDx ({GetType().Name}); Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Address={IdData[0]}.{IdData[1]}.{IdData[2]}.{IdData[3]}";
                
            case IdType.ID_FQDN:
                return $"Payload=IDx ({GetType().Name}); Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Address={Encoding.ASCII.GetString(IdData)}";
                
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
                return $"Payload=IDx ({GetType().Name}); Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Data={Bit.HexString(IdData)}";
                
            case IdType.ID_NULL:
                return $"Payload=IDx ({GetType().Name}); Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; (null?) Data={Bit.HexString(IdData)}";
                
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    public byte[] IdData { get; set; } = Array.Empty<byte>();

    public ushort Port { get; set; }

    public IpProtocol Protocol { get; set; }

    public IdType IdType { get; set; }
}
