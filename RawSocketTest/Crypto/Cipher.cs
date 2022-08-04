using System.Security.Cryptography;

namespace RawSocketTest.Crypto;

/// <summary>
/// Base class for an encryption cipher. Implements AES CBC
/// </summary>
/// <remarks>Neophytes should not trust Cipher</remarks>
public class Cipher
{
    public int KeyLength { get; }
    
    /// <summary>
    /// Create a new Cipher
    /// </summary>
    /// <param name="transform">Requested cipher type</param>
    /// <param name="keyLength">Key length in BITS</param>
    public Cipher(EncryptionTypeId transform, int keyLength)
    {
        if (transform != EncryptionTypeId.ENCR_AES_CBC) throw new Exception($"{transform.ToString()} is not supported, only {nameof(EncryptionTypeId.ENCR_AES_CBC)}");
        KeyLength = keyLength;
    }

    public virtual int BlockSize => 16;
    public virtual int KeySize => KeyLength / 8;

    public virtual byte[] Encrypt(byte[] key, byte[] iv, byte[] data)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.IV = iv;
        aes.Key = key;
        
        return aes.EncryptCbc(data, iv);
    }

    public virtual byte[] Decrypt(byte[] key, byte[] iv, byte[] data)
    {
        var aes = Aes.Create();
        aes.Key = key;
        
        return aes.DecryptCbc(data, iv);
    }

    public byte[] GenerateIv()
    {
        return RandomNumberGenerator.GetBytes(BlockSize);
    }
}