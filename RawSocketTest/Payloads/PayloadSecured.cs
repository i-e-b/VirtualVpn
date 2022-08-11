﻿using RawSocketTest.Crypto;

namespace RawSocketTest.Payloads;

/// <summary>
/// Represents an 'SK' message (type 46).
/// This is an encrypted container for further payloads
/// </summary>
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
        if (ikeCrypto is null) throw new Exception("Can't decrypt secured payload: crypto not provided");
        
        Console.WriteLine($"    Incoming secured payload. Offset is {idx}bytes. Encrypted data is {data.Length} bytes.");
        
        var ok = ikeCrypto.VerifyChecksum(data); // is this getting chopped too much?
        if (!ok) Console.WriteLine("CHECKSUM FAILED in RawSocketTest.Payloads.PayloadSecured.PayloadSecured");
        else  Console.WriteLine("Checksum passed in RawSocketTest.Payloads.PayloadSecured.PayloadSecured");
        
        ReadData(data, ref idx, ref nextPayload);
        
        
        
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