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
        return AesCipher(key).EncryptCbc(data, iv, PaddingMode.None);
    }

    public byte[] Decrypt(byte[] key, byte[] iv, byte[] data)
    {
        return AesCipher(key).DecryptCbc(data, iv, PaddingMode.None);
    }

    public byte[] GenerateIv()
    {
        return RandomNumberGenerator.GetBytes(BlockSize);
    }

    /// <summary>
    /// Create a AES-CBC cipher with key set.
    /// <para></para>
    /// NOTE: IV and padding-mode are critical to this working,
    /// but are ignored if set here.
    /// <para></para>
    /// The IKEv2 has its own padding mechanism, so we must always
    /// use dotnet PaddingMode <see cref="PaddingMode.None"/>
    /// otherwise decryption will fail.
    /// </summary>
    private static Aes AesCipher(byte[] key)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Key = key;
        return aes;
    }
}