﻿using System.Text;
using RawSocketTest.Helpers;

namespace RawSocketTest.Payloads;

/// <summary>
/// Flip side of <see cref="PayloadIDi"/>.
/// Todo: merge these? Like TS(i/r/x)
/// </summary>
public class PayloadIDr: MessagePayload
{
    public override PayloadType Type { get => PayloadType.IDr; set { } }
    
    public byte[] IdData { get; set; } = Array.Empty<byte>();

    public ushort Port { get; set; }

    public IpProtocol Protocol { get; set; }

    public IdType IdType { get; set; }
    
    // pvpn/message.py:329
    public PayloadIDr(IdType idType, byte[] idData, int protocol, int port)
    {
        throw new NotImplementedException();
    }

    public PayloadIDr(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        // IDr is usually inside an SK message.
        ReadData(data, ref idx, ref nextPayload);
    }
    
    public override int Size => HeaderSize + IdData.Length + 4;

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
                return $"Payload=IDr; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Address={IdData[0]}.{IdData[1]}.{IdData[2]}.{IdData[3]}";
                
            case IdType.ID_FQDN:
                return $"Payload=IDr; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Address={Encoding.ASCII.GetString(IdData)}";
                
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
                return $"Payload=IDr; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; Data={Bit.HexString(IdData)}";
                
            case IdType.ID_NULL:
                return $"Payload=IDr; Type={IdType.ToString()}; Protocol={Protocol.ToString()}; Port={Port}; (null?) Data={Bit.HexString(IdData)}";
                
            default:
                throw new ArgumentOutOfRangeException();
        }
    }
}