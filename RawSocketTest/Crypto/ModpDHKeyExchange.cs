using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using RawSocketTest.Helpers;

namespace RawSocketTest.Crypto;

// ike/util/dh.py:160

public class ModpDHKeyExchange
{
    private readonly int _group;
    private readonly BigInteger _generator;
    private BigInteger _privateKey;
    private readonly int _bits;
    private BigInteger _publicKey;
    private BigInteger _secret;

    public ModpDHKeyExchange(int group = 14, int n = 64)
    {
        _group = group;
        _generator = (BigInteger)2;
        _bits = n * 8;
        
        GeneratePrivateKey(n);
        GeneratePublicKey();
    }

    public byte[] DeriveSecret(byte[] otherKey)
    {
        var otherKeyInt = IntFromBytes(otherKey);
        var prime = GetPrime(_group);
        
        _secret = BigInteger.ModPow(otherKeyInt, _privateKey, prime);
        
        return SharedSecret();
    }

    private byte[] SharedSecret()
    {
        if (_secret == BigInteger.Zero) throw new Exception("Secret not yet derived");
        
        return _secret.ToByteArray(isBigEndian:true);
    }

    private void GeneratePublicKey()
    {
        var prime = GetPrime(_group);

        _publicKey = BigInteger.ModPow(_generator, _privateKey, prime);
    }
    

    public byte[] GetPublicKey()
    {
        // Pad to 256 with ending zeros
        var raw = BytesFromInt(_publicKey);
        var pad = 256 - raw.Length;
        if (pad == 0) return raw;
        
        return new byte[pad].Concat(raw).ToArray();
    }

    private BigInteger GetPrime(int group)
    {
        if (group == 14)
        {
            return IntFromBytes(_prime14);
        }
        
        throw new Exception($"Group {group} not currently supported");
    }

    private void GeneratePrivateKey(int byteSize)
    {
        var privateBytes = new byte[byteSize];
        RandomNumberGenerator.Fill(privateBytes);
        _privateKey = IntFromBytes(privateBytes);
    }

    private static BigInteger IntFromBytes(byte[] bytes) => new(bytes, isBigEndian:true, isUnsigned: false);
    private static byte[] BytesFromInt(BigInteger i) => i.ToByteArray(isBigEndian:true, isUnsigned: false);


    private static readonly byte[] _prime14 = Clean(@"
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF");

    private static byte[] Clean(string src)
    {
        var result = new List<byte>();
        
        var shift = 4;
        byte x = 0;
        
        foreach (char c in src)
        {
            if (c >= '0' && c <= '9')
            {
                x |= (byte)((c - '0') << shift);
            } else if (c >= 'A' && c <= 'F')
            {
                x |= (byte)(((10 + c) - 'A') << shift);
            } else continue; // not hex

            if (shift == 0)
            {
                result.Add(x);
                x = 0;
            }

            shift = 4 - shift;
        }
        
        return result.ToArray();
    }
}