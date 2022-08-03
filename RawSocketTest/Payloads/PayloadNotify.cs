using System.Text;

namespace RawSocketTest.Payloads;

public class PayloadNotify : MessagePayload
{
    public override PayloadType Type { get => PayloadType.NOTIFY; set { } }

    public IkeProtocolType ProtocolType { get; set; }
    public NotifyId NotificationType { get; set; }
    
    public int SpiSize { get; set; }
    public byte[] SpiData { get; set; } = Array.Empty<byte>();
    public byte[] InfoData { get; set; } = Array.Empty<byte>();

    public PayloadNotify(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }
    
    protected override void Serialise()
    {
        
    }
    
    protected override void Deserialise()
    {
        var idx = 0;
        ProtocolType = (IkeProtocolType)Data[idx++];
        SpiSize = Data[idx++];
        NotificationType = (NotifyId)Bit.ReadUInt16(Data, ref idx);
        
        if (SpiSize > 0) SpiData = new byte[SpiSize];
        for (int i = 0; i < SpiSize; i++)
        {
            SpiData[i] = Data[idx++];
        }
        
        var remains = Data.Length - 4 - SpiSize;
        if (remains > 0) InfoData = new byte[remains];
        for (int i = 0; i < remains; i++)
        {
            InfoData[i] = Data[idx++];
        }
    }

}