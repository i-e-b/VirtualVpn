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

    public byte[] IdData { get; set; } = Array.Empty<byte>();

    public ushort Port { get; set; }

    public IpProtocol Protocol { get; set; }

    public IdType IdType { get; set; }
}