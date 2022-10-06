using System.Security.Cryptography;
using System.Text;

namespace VirtualVpn.Web;

/// <summary>
/// A helper class to give compatibility between dotnet core 3.1, and dotnet 6
/// </summary>
public class AesCryptoService
{
    private readonly byte[] _key;

    /// <summary>
    /// Generate a new AES encryptor with the given key.
    /// </summary>
    public AesCryptoService(byte[] key)
    {
        _key = key;
        using var aesAlg = Aes.Create();
        BlockSize = aesAlg.BlockSize;
    }

    /// <summary>
    /// Size of crypto blocks
    /// </summary>
    public int BlockSize { get; }

    /// <summary>
    /// Encode text as UTF8, then encrypt
    /// </summary>
    public byte[] EncryptStringToBytes(string plainText, byte[] iv)
    {
        if (plainText == null || plainText.Length <= 0) throw new ArgumentNullException(nameof(plainText));
        if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));
        byte[] encrypted;


        using (var aesAlg = Aes.Create())//AesCryptoServiceProvider())
        {
            aesAlg.Key = _key;
            aesAlg.IV = iv;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                    {
                        swEncrypt.Write(plainText);
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;
    }

    /// <summary>
    /// Decrypt data, then decode as UTF8 string
    /// </summary>
    public string DecryptStringFromBytes(byte[] cipherText, byte[] iv)
    {
        if (cipherText == null || cipherText.Length <= 0) throw new ArgumentNullException(nameof(cipherText));
        if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

        using var aesAlg = Aes.Create();
        aesAlg.Key = _key;
        aesAlg.IV = iv;
        aesAlg.Mode = CipherMode.CBC;
        aesAlg.Padding = PaddingMode.PKCS7;

        var decrypt = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        using var msDecrypt = new MemoryStream(cipherText);
        using var csDecrypt = new CryptoStream(msDecrypt, decrypt, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8);
        
        return srDecrypt.ReadToEnd();
    }

    /// <summary>
    /// Generate a SHA256 HMAC value for data+key
    /// </summary>
    public static byte[] HashData(byte[] key, byte[] source)
    {
        // The pre dotnet-6 hash libraries are particularly bad,
        // and some methods try to cast between invalid types in the platform libraries.
        // This is the only combination of calls that seems to work.
        
        using var algorithm = CryptoConfig.CreateFromName("HMACSHA256") as HMACSHA256;
        if (algorithm == null) throw new Exception("Unacceptable SHA256 HMAC. Failed to load matching algorithm from config");
        
        algorithm.Key = key;
        return algorithm.ComputeHash(source);
    }
}