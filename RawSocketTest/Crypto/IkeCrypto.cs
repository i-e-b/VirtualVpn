using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using static System.Numerics.BigInteger;

namespace RawSocketTest.Crypto;

/// <summary>
/// Wrapper around standard cryptography functions.
/// This adds and removes various headers, checksums, and padding as required.
/// </summary>
public class IkeCrypto
{
    private readonly Cipher _cipher;
    private readonly Integrity? _integrity;
    private readonly Prf? _prf;
    private readonly byte[] _skE;
    private readonly byte[]? _skA;
    private readonly byte[]? _skP;
    private readonly byte[]? _lastIv;
    private readonly Dictionary<uint, byte[]> _vectors;

    public IkeCrypto(Cipher cipher, Integrity? integrity, Prf? prf, byte[] skE, byte[]? skA, byte[]? skP, byte[]? iv)
    {
        _cipher = cipher;
        _integrity = integrity;
        _prf = prf;
        _skE = skE;
        _skA = skA;
        _skP = skP;

        _vectors = new Dictionary<uint, byte[]>();
        if (iv is not null) _vectors.Add(0, iv);

        _lastIv = null;
    }

    /// <summary>
    /// Recover encrypted data, and the chain byte used
    /// </summary>
    public byte[] Decrypt(byte[] encrypted, out IpProtocol nextHeader)
    {
        var blockSize = _cipher.BlockSize;
        var hashSize = _integrity?.HashSize ?? 0;
        var cipherSize = encrypted.Length - blockSize - hashSize;

        // encrypted data is [ init vec ][ cipher text ][ checksum ]
        var iv = encrypted.Take(blockSize).ToArray();
        var cipherText = encrypted.Skip(blockSize).Take(cipherSize).ToArray();

        // decrypted data is [ message data ][ padding ][ pad len ][ carry-over ]
        var decrypted = _cipher.Decrypt(_skE, iv, cipherText);
        nextHeader = (IpProtocol)decrypted[^1]; // last element
        var padLength = decrypted[^2]; // second-last element
        var messageBytes = decrypted.Length - padLength - 2;

        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Encrypt plain data, using a chain byte
    /// </summary>
    public byte[] Encrypt(IpProtocol nextHeader, byte[] plain)
    {
        var blockSize = _cipher.BlockSize;
        var iv = _cipher.GenerateIv();
        var padLength = blockSize - ((plain.Length + 1) % blockSize) - 1;

        var pad = new byte[padLength];
        var tail = new[] { (byte)padLength, (byte)nextHeader };
        var checksumPad = (_integrity is null) ? Array.Empty<byte>() : new byte[_integrity.HashSize];

        var payload = plain.Concat(pad).Concat(tail).ToArray();
        var encrypted = _cipher.Encrypt(_skE, iv, payload);

        var packet = iv.Concat(encrypted).Concat(checksumPad).ToArray();

        return packet;
    }

    /// <summary>
    /// Return true if the checksum matches expectations
    /// </summary>
    public bool VerifyChecksum(byte[] encrypted)
    {
        if (_integrity is null) return true;
        if (_skA is null) return false;

        // read just the main body
        var payloadLength = encrypted.Length - _integrity.HashSize;
        var mainPayload = encrypted.Take(payloadLength).ToArray();

        // compute
        var expected = _integrity.Compute(_skA, mainPayload);

        // copy
        for (int i = 0; i < expected.Length; i++)
        {
            if (expected[i] != encrypted[i + payloadLength]) return false;
        }

        return true;
    }

    /// <summary>
    /// Calculate and inject a checksum into an encrypted message
    /// </summary>
    public void AddChecksum(byte[] encrypted)
    {
        if (_integrity is null) return;
        if (_skA is null) throw new Exception($"Checksum is present, but no checksum key was given ({nameof(_skA)})");

        // read just the main body
        var payloadLength = encrypted.Length - _integrity.HashSize;
        var mainPayload = encrypted.Take(payloadLength).ToArray();

        // compute
        var sum = _integrity.Compute(_skA, mainPayload);

        // copy
        for (int i = 0; i < sum.Length; i++)
        {
            encrypted[i + payloadLength] = sum[i];
        }
    }

    /// <summary>
    /// Decrypt data from negotiation phase (phase 2?)
    /// </summary>
    public byte[] Decrypt1(byte[] encrypted, uint messageId, bool removePad = false)
    {
        // get initialisation vector
        EnsureInitVector(messageId);
        var iv = _vectors[messageId];

        // decrypt message
        var decrypted = _cipher.Decrypt(_skE, iv, encrypted);

        // update IV
        var mainMessage = encrypted.Length - _cipher.BlockSize;
        _vectors[messageId] = encrypted.Skip(mainMessage).ToArray();

        // By the spec, we should remove padding from `plain` here, but
        // source material says "do not remove padding according to ios cisco ipsec bug" (see pvpn/crypto.py:108 )
        if (!removePad) return decrypted;

        // remove padding
        var padLength = decrypted[^1]; // second-last element
        var messageBytes = decrypted.Length - padLength - 1;

        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Encrypt data from negotiation phase (phase 2?)
    /// </summary>
    public byte[] Encrypt1(byte[] plain, uint messageId)
    {
        // get initialisation vector
        EnsureInitVector(messageId);
        var iv = _vectors[messageId];

        // pad message to block size, with space for padding length byte. 
        var blockSize = _cipher.BlockSize;
        var padLength = blockSize - ((plain.Length + 1) % blockSize);

        var pad = new byte[padLength];
        var tail = new[] { (byte)padLength };

        var payload = plain.Concat(pad).Concat(tail).ToArray();

        // encrypt the payload
        var encrypted = _cipher.Encrypt(_skE, iv, payload);

        // update IV
        var mainMessage = encrypted.Length - _cipher.BlockSize;
        _vectors[messageId] = encrypted.Skip(mainMessage).ToArray();

        return encrypted;
    }

    /// <summary>
    /// Make sure we have enough data and algorithms set to read an IV.
    /// Throws if not possible.
    /// </summary>
    private void EnsureInitVector(uint messageId)
    {
        if (_prf is null) throw new Exception("Hash function (PRF) has not been agreed");
        if (!_vectors.ContainsKey(0)) throw new Exception("First initialisation vector has not been set");

        // make sure we have an iv
        if (!_vectors.ContainsKey(messageId))
        {
            var blockSize = _cipher.BlockSize;
            var src = _vectors[0].Concat(Bit.UInt32ToBytes(messageId)).ToArray();
            var fullHash = _prf.Hash(_skE, src);
            var slice = fullHash.Length == blockSize ? fullHash : fullHash.Take(blockSize).ToArray();
            _vectors.Add(messageId, slice);
        }
    }
    
    // TODO: move this stuff into its own class? ...


    public static void DiffieHellman(DhId group, byte[] peerData, out byte[] publicKey, out byte[] sharedSecret)
    {
        // pvpn/crypto.py:213
        
        if (!_primes.ContainsKey(group)) throw new Exception($"Prime group {group.ToString()} is not supported");
        
        var peer = new BigInteger(peerData, isBigEndian:true);
        var prime = _primes[group];
        
        var p = prime.P;
        var l = prime.L;
        var a = NextBigInteger(p>>8, p);

        BigInteger pub, shs;

        if (prime.G_Function is not null)
        {
            publicKey = prime.G_Function(a, l);
            sharedSecret = prime.G_Function(a, peer);
            return;
        }
        
        if (prime.G_Tuple is not null)
        {
            var g = prime.G_Tuple;
            
            pub = ec_mul(g[0], l, a, p, g[1]);
            shs = ec_mul(peer, l, a, p, g[1]);


            publicKey = ToBytesPadded(pub, l * 2);
            sharedSecret = ToBytesPadded(shs, l * 2).Take(l).ToArray();
            return;
        }
        
        if (prime.G_Value is not null)
        {
            var g = prime.G_Value.Value;
            pub = ModPow(g, a, p);
            shs = ModPow(peer, a, p);
            
            publicKey = ToBytesPadded(pub, l);
            sharedSecret = ToBytesPadded(shs, l);
            return;
        }
        
        throw new Exception($"Invalid prime definition for group {group.ToString()}");
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    private static BigInteger ec_mul(BigInteger P, int l, BigInteger i, BigInteger p, BigInteger a)
    {
        var r = Zero;
        while (i > 0)
        {
            if ((i & 1) != 0)
            {
                r = ec_add(r, P, l<<3, p, a);
            }
            i >>= 1;
            P = ec_add(P,P, l<<3, p,a);
        }
        return r;
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    private static BigInteger ec_add(BigInteger P, BigInteger Q, int l, BigInteger p, BigInteger a)
    {
        BigInteger z;
        if (P == 0) return Q;
        if (P == Q)
        {
            z = (3 * (P >> l) * (P >> l) + a) * ModPow(2 * (P & (One << l) - 1), p - 2, p);
        }
        else
        {
            z = ((Q & (One << l) - 1) - (P & (One << l) - 1)) * ModPow((Q >> l) - (P >> l), p - 2, p); 
        }
        var x = (z * z - (P >> l) - (Q >> l)) % p;
        return x << l | (z * ((P >> l) - x) - (P & (1 << l) - 1)) % p;
    }

    /// <summary>
    /// Generates a random BigInteger between start and end (non-inclusive).
    /// </summary>
    /// <param name="start">The lower bound.</param>
    /// <param name="end">The upper bound (non-inclusive).</param>
    /// <returns>A random BigInteger between start and end (non-inclusive)</returns>
    /// <remarks>From https://gist.github.com/rharkanson/50fe61655e80488fcfec7d2ee8eff568</remarks>
    private static BigInteger NextBigInteger(BigInteger start, BigInteger end)
    {
        if (start == end) return start;

        var res = end;

        // Swap start and end if given in reverse order.
        if (start > end)
        {
            end = start;
            start = res;
            res = end - start;
        }
        else
            // The distance between start and end to generate a random BigInteger between 0 and (end-start) (non-inclusive).
            res -= start;

        var bs = res.ToByteArray();

        // Count the number of bits necessary for res.
        var bits = 8;
        byte mask = 0x7F;
        while ((bs[^1] & mask) == bs[^1])
        {
            bits--;
            mask >>= 1;
        }
        bits += 8 * bs.Length;

        // Generate a random BigInteger that is the first power of 2 larger than res, 
        // then scale the range down to the size of res,
        // finally add start back on to shift back to the desired range and return.
        return NextBigInteger(bits + 1) * res / Pow(2, bits + 1) + start;
    }
    
    /// <summary>
    /// Generates a random positive BigInteger between 0 and 2^bitLength (non-inclusive).
    /// </summary>
    /// <param name="bitLength">The number of random bits to generate.</param>
    /// <returns>A random positive BigInteger between 0 and 2^bitLength (non-inclusive).</returns>
    /// <remarks>From https://gist.github.com/rharkanson/50fe61655e80488fcfec7d2ee8eff568</remarks>
    private static BigInteger NextBigInteger(int bitLength)
    {
        if (bitLength < 1) return BigInteger.Zero;

        var bytes = bitLength / 8;
        var bits = bitLength % 8;

        // Generates enough random bytes to cover our bits.
        var bs = new byte[bytes + 1];
        RandomNumberGenerator.Fill(bs);

        // Mask out the unnecessary bits.
        var mask = (byte)(0xFF >> (8 - bits));
        bs[^1] &= mask;

        return new BigInteger(bs);
    }

    // pvpn/crypto.py:188
    // This will need testing to see if it even vaguely works
    private static readonly Dictionary<DhId, DhSrc> _primes = new Dictionary<DhId, DhSrc>
    {
        // simple exponent
        { DhId.DH_1, DhSrc.Exp(2, 96, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF") },
        { DhId.DH_2, DhSrc.Exp(2, 128, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF") },
        { DhId.DH_5, DhSrc.Exp(2, 192, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF") },
        { DhId.DH_14, DhSrc.Exp(2, 256, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF") },
        { DhId.DH_15, DhSrc.Exp(2, 384, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF") },
        { DhId.DH_16, DhSrc.Exp(2, 512, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF") },
        { DhId.DH_17, DhSrc.Exp(2, 768, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF") },
        { DhId.DH_18, DhSrc.Exp(2, 1024, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF") },

        // elliptic curves with negatives
        { DhId.DH_19, DhSrc.Elliptic(32, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",  "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", "-3") },
        { DhId.DH_20, DhSrc.Elliptic(48, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",  "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", "-3") },
        { DhId.DH_21, DhSrc.Elliptic(66, "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",  "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", "-3") },
        
        // exponents, but bigger
        { DhId.DH_22, DhSrc.ExpBig(128, "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371","A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5") },
        { DhId.DH_23, DhSrc.ExpBig(256, "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F",  "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA") },
        { DhId.DH_24, DhSrc.ExpBig(256, "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597",  "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659") },
        
        // elliptic curves again
        { DhId.DH_25, DhSrc.Elliptic(24, @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",  @"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811", @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC") },
        { DhId.DH_26, DhSrc.Elliptic(28, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",  "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", @"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE") },
        { DhId.DH_27, DhSrc.Elliptic(28, "D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF",  "0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD", "68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43") },
        { DhId.DH_28, DhSrc.Elliptic(32, "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",  "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9") },
        { DhId.DH_29, DhSrc.Elliptic(48, "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",  "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826") },
        { DhId.DH_30, DhSrc.Elliptic(64, "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",  "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F8227DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA") },

        // complex curves
        { DhId.DH_31, DhSrc.Complex(32, X25519, 9) },
        { DhId.DH_32, DhSrc.Complex(56, X448, 5) },
    };

    // Don't ask me how this works. Just pray.
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    private static BigInteger ecScalar(BigInteger k, BigInteger u, BigInteger p, int a24, int bits)
    {
        var x2 = One;
        var x3 = u;
        var z2 = Zero;
        var z3 = One;
        var swap = Zero;

        for (int t = bits-1; t >= 0; t--)
        {
            var kT = (k>>t) & 1;
            
            var test = swap ^ kT;
            if (!test.IsZero) // mix
            {
                (x2, x3, z2, z3) = (x3, x2, z3, z2);
            }
            swap = kT;
            
            var A = x2+z2;
            var B = x2-z2;
            var C = x3+z3;
            var D = x3-z3;
            
            var AA = A * A;
            var BB = B * B;
            var DA = D * A;
            var CB = C * B;
            
            var E = AA - BB;
            x3 = ModPow(DA+CB, 2, p);
            z3 = u * ModPow(DA - CB, 2, p) % p;
            x2 = AA * BB % p;
            z2 = E * (AA + a24*E) % p;
        }

        if (!swap.IsZero)
        {
            (x2, _/*x3*/, z2, _/*z3*/) = (x3, x2, z3, z2);
        }
        
        return x2 * ModPow(z2, p-2, p) % p;
    }
    
    private static byte[] X25519(BigInteger k, BigInteger u)
    {
        var _1 = One;
        
        k = k & ((_1 << 256) - (_1 << 255) - 8) | (_1 << 254);
        var exp = Pow(2, 255) - 19;
        return ToBytesPadded(ecScalar(k, u, exp, 121665, 255), 32);
    }

    private static byte[] X448(BigInteger k, BigInteger u)
    {
        var _1 = One;
        
        k = k & (-4) | (_1 << 447);
        var exp = Pow(2, 448) - Pow(2, 224) - 1;
        return ToBytesPadded(ecScalar(k,u, exp, 39081, 448), 56);
    }
    
    private static byte[] ToBytesPadded(BigInteger value, int len)
    {
        var vb = value.ToByteArray(isBigEndian:true);
        var pad = len - vb.Length;
        
        if (pad < 0) throw new Exception($"Could not represent value in {len} bytes, as it is {vb.Length} bytes long");
        if (pad == 0) return vb;
        
        var padBytes = new byte[pad];
        return padBytes.Concat(vb).ToArray();
    }

    public static bool IsSupported(DhId transformId) => _primes.ContainsKey(transformId);
}

internal class DhSrc
{
    public BigInteger P;
    public Func<BigInteger, BigInteger, byte[]>? G_Function;
    public BigInteger[]? G_Tuple;
    public BigInteger? G_Value;
    public int L;

    public static DhSrc Complex(int ps, Func<BigInteger, BigInteger, byte[]> g, int l)
    {
        return new DhSrc
        {
            P = new BigInteger(2) << ps,
            G_Value = null,
            G_Function = g,
            G_Tuple = null,
            L = l
        };
    }

    public static DhSrc Exp(int l, int gi, string p)
    {
        return new DhSrc
        {
            P = Parse(p, NumberStyles.HexNumber),
            G_Value = new BigInteger(gi),
            G_Function = null,
            G_Tuple = null,
            L = l
        };
    }

    public static DhSrc ExpBig(int l, string p, string g)
    {
        return new DhSrc
        {
            P = Parse(p, NumberStyles.HexNumber),
            G_Value = Parse(g, NumberStyles.HexNumber),
            G_Function = null,
            G_Tuple = null,
            L = l
        };
    }
    
    public static DhSrc Elliptic(int l, string p, params string[] ge)
    {
        return new DhSrc
        {
            P = Parse(p, NumberStyles.HexNumber),
            G_Value = null,
            G_Function = null,
            G_Tuple = ge.Select(s => s.StartsWith('-') ? Parse(s, NumberStyles.Integer) : Parse(s, NumberStyles.HexNumber)).ToArray(),
            L = l
        };
    }
}