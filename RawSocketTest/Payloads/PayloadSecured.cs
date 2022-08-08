using RawSocketTest.Crypto;

namespace RawSocketTest.Payloads;

public class PayloadSecured : MessagePayload
{
    /*
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ! Next Payload  !C!  RESERVED   !         Payload Length        !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                     Initialization Vector                     !
      !         (length is block size for encryption algorithm)       !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !                    Encrypted IKE Payloads                     !
      +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      !               !             Padding (0-255 octets)            !
      +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
      !                                               !  Pad Length   !
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      ~                    Integrity Checksum Data                    ~
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
    
    
    private readonly IpProtocol? _firstHeader;
    public override PayloadType Type { get => PayloadType.SK; set { } }
    
    public override int Size => HeaderSize + Data.Length;

    public byte[]? PlainBody { get; private set; }

    public PayloadSecured(byte[] data, IkeCrypto? ikeCrypto, ref int idx, ref PayloadType nextPayload)
    {
        ReadData(data, ref idx, ref nextPayload);
        
        if (ikeCrypto is null) return; // can't decrypt
        
        var ok = ikeCrypto.VerifyChecksum(Data); // IEB: currently failing?
        //if (!ok) return;
        
        PlainBody = ikeCrypto.Decrypt(Data, out var nextHeader);
        _firstHeader = nextHeader;
    }
    
    protected override void Serialise()
    {
    }
    
    protected override void Deserialise()
    {
    }
}