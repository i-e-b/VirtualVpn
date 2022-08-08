using System.Security.Cryptography;

namespace RawSocketTest.Crypto;

/// <summary>
/// Base class for an encryption cipher. Implements AES CBC
/// </summary>
/// <remarks>Neophytes should not trust Cipher</remarks>
public class Cipher
{
    public int KeyLength { get; }
    
    public EncryptionTypeId CipherType => EncryptionTypeId.ENCR_AES_CBC; // if we support more, then store selected here

    public override string ToString() => $"Type={CipherType.ToString()} Block={BlockSize} bytes Key={KeySize} bytes;";

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

    public static bool IsSupported(EncryptionTypeId transform)
    {
        return transform == EncryptionTypeId.ENCR_AES_CBC;
    }

    public int BlockSize => 16;
    public int KeySize => KeyLength / 8;

    public byte[] Encrypt(byte[] key, byte[] iv, byte[] data)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.IV = iv;
        aes.Key = key;
        
        return aes.EncryptCbc(data, iv);
    }

    public byte[] Decrypt(byte[] key, byte[] iv, byte[] data)
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