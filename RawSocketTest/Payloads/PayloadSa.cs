using RawSocketTest.Crypto;
using RawSocketTest.Helpers;
using RawSocketTest.Payloads.PayloadSubunits;

namespace RawSocketTest.Payloads;

// pvpn.message.PayloadSA - pvpn/message.py:286
public class PayloadSa : MessagePayload
{
    private const byte PayloadHasMore = 2;
    private const byte PayloadLastOne = 0;
    
    public PayloadSa(byte[] data, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
    }

    public PayloadSa(Proposal proposal)
    {
        Proposals.Add(proposal);
    }

    public override PayloadType Type { get => PayloadType.SA; set { } }
    public override int Size => HeaderSize + Proposals.Sum(p=>p.Size) + Proposals.Count * 4;

    public List<Proposal> Proposals { get; set; } = new();
    
    

    public override string Describe()
    {
        return $"Payload=SA; ProposalCount={Proposals.Count};";
    }
    
    protected override void Serialise()
    {
        // chain proposals
        Data = new byte[Size - HeaderSize];

        var idx = 0;
        for (int i = 0; i < Proposals.Count; i++)
        {
            var more = (i == Proposals.Count - 1) ? PayloadLastOne : PayloadHasMore; // this is NOT a count, it's a flag, which is different from other 'more' flags
            
            var proposal = Proposals[i];
            var proposalBytes = proposal.Serialise();
            var length = proposalBytes.Length+4;
            
            Data[idx++] = (byte)more;
            idx++; // unused
            Bit.WriteUInt16((ushort)length, Data, ref idx);
            for (int k = 0; k < proposalBytes.Length; k++)
            {
                Data[idx++] = proposalBytes[k];
            }
        }
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
        // var uniqueTransforms = src.Transforms.DistinctBy(trans => trans.Type).ToList();
        
        // what we actually want is to strip any transforms we don't support
        var supportedTransforms = src.Transforms.Where(IsSupported).ToList();
        
        // and then just pick one of each type
        var uniqueSupportedTransforms = supportedTransforms.DistinctBy(trans => trans.Type).ToList();
        

        var prop = new Proposal
        {
            Number = src.Number,
            Protocol = src.Protocol,
            SpiSize = src.SpiSize,
            SpiData = src.SpiData,
            TransformCount = (byte)uniqueSupportedTransforms.Count,
            Transforms = uniqueSupportedTransforms
        };
        
        return prop;
    }

    private bool IsSupported(Transform transform)
    {
        var type = transform.Type;
        return type switch
        {
            TransformType.ENCR => Cipher.IsSupported((EncryptionTypeId)transform.Id),
            TransformType.PRF => Prf.IsSupported((PrfId)transform.Id),
            TransformType.INTEG => Integrity.IsSupported((IntegId)transform.Id),
            TransformType.DH => gmpDh.GmpDhParameters.IsSupported((DhId)transform.Id),
            TransformType.ESN => (EsnId)transform.Id == EsnId.NO_ESN,
            _ => false
        };
    }
}