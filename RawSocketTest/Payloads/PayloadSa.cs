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

    public Proposal? GetProposalFor(EncryptionTypeId type)
    {
        var src = Proposals.FirstOrDefault(p=>
            p.Transforms.Any(t=> t.Type == TransformType.ENCR && t.Id == (uint)type)
            );
        
        if (src is null) return null;
        
        // source does a "remove redundancy" phase. See pvpn/message.py:275
        
        /*var typesSeen = new HashSet<TransformType>();
        var uniqueTransforms = new List<Transform>();
        foreach (var transform in src.Transforms)
        {
            if (typesSeen.Contains(transform.Type)) continue;
            
            typesSeen.Add(transform.Type);
            uniqueTransforms.Add(transform);
        }*/
        
        var uniqueTransforms = src.Transforms.DistinctBy(trans => trans.Type).ToList();

        var prop = new Proposal
        {
            Number = src.Number,
            Protocol = src.Protocol,
            SpiSize = src.SpiSize,
            SpiData = src.SpiData,
            TransformCount = (byte)uniqueTransforms.Count,
            Transforms = uniqueTransforms
        };
        
        return prop;
    }
}