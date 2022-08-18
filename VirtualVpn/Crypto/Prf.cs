// ReSharper disable InconsistentNaming

using System.Security.Cryptography;
using VirtualVpn.Enums;

namespace VirtualVpn.Crypto;

/// <summary>
/// "PRF" in IKE-talk is "pseudo-random function", or a hash function.
/// https://security.stackexchange.com/questions/57656/prf-ike-and-hash-function
/// </summary>
public class Prf
{
    /// <summary>
    /// This should be ASCII encoded for the pad bytes.
    /// <para></para>
    /// AUTH [32 bytes] = prf(prf( PSK, "Key Pad for IKEv2" ), {msg bytes})
    /// </summary>
    /// <remarks>
    /// Due to rotating keys, this should be different for each session
    /// </remarks>
    public const string IKEv2_KeyPad = "Key Pad for IKEv2"; // someone had an inventive day.
    
    private readonly PrfId _transform;
    public int KeySize { get; }
    
    private readonly Func<byte[],byte[],byte[]> _algo;

    public Prf(PrfId transform)
    {
        _transform = transform;
        switch (transform)
        {
            case PrfId.PRF_HMAC_MD5:
                _algo = HMACMD5.HashData;
                KeySize = 16;
                break;
            case PrfId.PRF_HMAC_SHA1:
                _algo = HMACSHA1.HashData;
                KeySize = 20;
                break;
            case PrfId.PRF_HMAC_SHA2_256:
                _algo = HMACSHA256.HashData;
                KeySize = 32;
                break;
            case PrfId.PRF_HMAC_SHA2_384:
                _algo = HMACSHA384.HashData;
                KeySize = 48;
                break;
            case PrfId.PRF_HMAC_SHA2_512:
                _algo = HMACSHA512.HashData;
                KeySize = 64;
                break;
            
            case PrfId.PRF_AES128_CMAC:
            case PrfId.PRF_AES128_XCBC:
            case PrfId.PRF_HMAC_TIGER:
                throw new Exception($"Hash: PRF function {transform.ToString()} is not supported");
            
            default:
                throw new ArgumentOutOfRangeException(nameof(transform), transform, null);
        }
    }

    public override string ToString() => $"Function={_transform.ToString()} KeySize={KeySize};";

    public static bool IsSupported(PrfId transformId)
    {
        switch (transformId)
        {
            case PrfId.PRF_HMAC_MD5:
            case PrfId.PRF_HMAC_SHA1:
            case PrfId.PRF_HMAC_SHA2_256:
            case PrfId.PRF_HMAC_SHA2_384:
            case PrfId.PRF_HMAC_SHA2_512:
                return true;
            
            case PrfId.PRF_AES128_CMAC:
            case PrfId.PRF_AES128_XCBC:
            case PrfId.PRF_HMAC_TIGER:
                return false;
            
            default:
                throw new ArgumentOutOfRangeException(nameof(transformId), transformId, null);
        }
    }

    
    /// <summary>
    /// Produce a keyed HMAC of the data
    /// </summary>
    public byte[] Hash(byte[] key, byte[] data) => _algo(key, data);

    /// <summary>
    /// Generate a large sequence of bytes using a key and seed, by folding
    /// multiple rounds of data together. Then truncates?
    /// </summary>
    public byte[] PrfPlus(byte[] key, byte[] seed, int byteCount)
    {
        var ret = new List<byte>();
        var prev = Array.Empty<byte>();
        var round = 1;
        while (ret.Count < byteCount)
        {
            var data = prev.Concat(seed).Concat(new[]{(byte)round}).ToArray();
            prev = Hash(key, data);
            
            ret.AddRange(prev);
            round++;
        }
        return ret.GetRange(0, byteCount).ToArray();
    }

    public IEnumerable<byte> HashFont_Old(byte[] key, byte[] seed, bool includeCount = true)
        {
        /*def prfplus(key, data, n):
    ret = bytes()
    prev = bytes()
    round = 1
    while len(ret) < n:
        prev = prf(key, prev + data + pack("!B", round))
        ret += prev
        round += 1
    return ret[:n]*/
        
        
        var bytes = Array.Empty<byte>();
        for (var i = 1; i < 1024; i++)
        {
            var feed = bytes.Concat(seed);
            if (includeCount) feed = feed.Concat(new[]{(byte)i});
            
            bytes = Hash(key, feed.ToArray());
            foreach (var b in bytes)
            {
                yield return b;
            }
        }
    }

}