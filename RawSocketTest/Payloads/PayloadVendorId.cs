using System.Text;

namespace RawSocketTest.Payloads;

public class PayloadVendorId : MessagePayload
{
    private string _description = "";
    public override PayloadType Type { get => PayloadType.VENDOR; set { } }

    public string Description
    {
        get => _description;
        set { _description = value; 
            Data = Encoding.UTF8.GetBytes(value);
        }
    }

    public override int Size => HeaderSize + Data.Length;

    public PayloadVendorId(string message)
    {
        Description = message;
        Data = Encoding.UTF8.GetBytes(message);
    }
    
    public PayloadVendorId(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }
    
    protected override void Serialise()
    {
        Data = Encoding.UTF8.GetBytes(Description);
    }
    
    protected override void Deserialise()
    {
        Description = Encoding.UTF8.GetString(Data);
    }
}