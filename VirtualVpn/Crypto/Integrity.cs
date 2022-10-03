using System.Security.Cryptography;
using VirtualVpn.Enums;
using VirtualVpn.Helpers;

namespace VirtualVpn.Crypto;

/// <summary>
/// Hash function with truncated lengths, used for checksums
/// <para></para>
/// This is basically the same as <see cref="Prf"/>, but IKE has
/// a second set of IDs for it, and uses it in different places.
/// </summary>
public class Integrity
{
    private readonly IntegId _transform;
    public int KeySize { get; }
    public int HashSize { get; }
   
    private readonly Func<byte[],byte[],byte[]> _algo; 
    
    public Integrity(IntegId transform)
    {
        _transform = transform;
        switch (transform)
        {
            case IntegId.AUTH_NONE:
            case IntegId.AUTH_DES_MAC:
            case IntegId.AUTH_KPDK_MD5:
            case IntegId.AUTH_AES_XCBC_96:
            case IntegId.AUTH_AES_CMAC_96:
            case IntegId.AUTH_AES_128_GMAC:
            case IntegId.AUTH_AES_192_GMAC:
            case IntegId.AUTH_AES_256_GMAC:
                throw new Exception($"Integrity: PRF function {transform.ToString()} is not supported");
                
            case IntegId.AUTH_HMAC_MD5_96:
                KeySize=16;
                HashSize=12;
                _algo = HMACMD5.HashData;
                break;
            case IntegId.AUTH_HMAC_SHA1_96:
                KeySize=20;
                HashSize=12;
                _algo = HMACSHA1.HashData;
                break;
            case IntegId.AUTH_HMAC_MD5_128:
                KeySize=16;
                HashSize=16;
                _algo = HMACMD5.HashData;
                break;
            case IntegId.AUTH_HMAC_SHA1_160:
                KeySize=20;
                HashSize=20;
                _algo = HMACSHA1.HashData;
                break;
            case IntegId.AUTH_HMAC_SHA2_256_128:
                KeySize=32;
                HashSize=16;
                _algo = HMACSHA256.HashData;
                break;
            case IntegId.AUTH_HMAC_SHA2_384_192:
                KeySize=48;
                HashSize=24;
                _algo = HMACSHA384.HashData;
                break;
            case IntegId.AUTH_HMAC_SHA2_512_256:
                KeySize=64;
                HashSize=32;
                _algo = HMACSHA512.HashData;
                break;
            
            default:
                throw new ArgumentOutOfRangeException(nameof(transform), transform, null);
        }
    }

    public override string ToString() => $"Algorithm={_transform.ToString()} KeySize={KeySize} HashSize={HashSize};";

    public byte[] Compute(byte[] key, byte[] data)
    {
        var full = _algo(key, data);
        Log.Crypto("------HASH----->\r\n" + Bit.Describe("key", key) + Bit.Describe("data", data) + Bit.Describe("ICV (hash)", full));
        if (full.Length <= HashSize) return full;
        return full.Take(HashSize).ToArray();
    }
    
    public static bool IsSupported(IntegId transformId)
    {
        switch (transformId)
        {
            case IntegId.AUTH_NONE:
            case IntegId.AUTH_DES_MAC:
            case IntegId.AUTH_KPDK_MD5:
            case IntegId.AUTH_AES_XCBC_96:
            case IntegId.AUTH_AES_CMAC_96:
            case IntegId.AUTH_AES_128_GMAC:
            case IntegId.AUTH_AES_192_GMAC:
            case IntegId.AUTH_AES_256_GMAC:
                return false;
                
            case IntegId.AUTH_HMAC_MD5_96:
            case IntegId.AUTH_HMAC_SHA1_96:
            case IntegId.AUTH_HMAC_MD5_128:
            case IntegId.AUTH_HMAC_SHA1_160:
            case IntegId.AUTH_HMAC_SHA2_256_128:
            case IntegId.AUTH_HMAC_SHA2_384_192:
            case IntegId.AUTH_HMAC_SHA2_512_256:
                return true;
                
            default:
                throw new ArgumentOutOfRangeException(nameof(transformId), transformId, null);
        }
    }
}