namespace RawSocketTest.Payloads;

// pvpn.message.PayloadSA - pvpn/message.py:286
public class PayloadSa : MessagePayload
{
    public PayloadSa(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public override PayloadType Type { get => PayloadType.SA; set { } }

    public List<Proposal> Proposals { get; set; } = new();
    
    protected override void Serialise()
    {
        // chain proposals
    }
    
    protected override void Deserialise()
    {
        // un-chain proposals
        byte more = 1;
        int idx = 0;
        int end = Data.Length - 4;

        while (more > 0 && idx < end)
        {
            // each proposal has a sub-header:
            more = Data[idx++];
            idx++; // unused
            var length = Bit.ReadUInt16(Data, ref idx);
            
            // and a variable quantity of data:
            Proposals.Add(Proposal.Parse(Data, length, ref idx));
        }
    }
}