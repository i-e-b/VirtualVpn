using System.Text;

namespace RawSocketTest.Payloads;

public class PayloadVendorId : MessagePayload
{
    public override PayloadType Type { get => PayloadType.VENDOR; set { } }

    public string Description { get; set; } = "";

    public PayloadVendorId(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }
    
    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
        Description = Encoding.UTF8.GetString(Data);
    }
}