using System.Security.Cryptography;
using System.Text;
using VirtualVpn.Helpers;

namespace VirtualVpn.Web;

/// <summary>
/// A helper class to give compatibility between dotnet core 3.1, and dotnet 6
/// </summary>
public class AesCryptoService
{
    private readonly byte[] _key;

    public AesCryptoService(byte[] key)
    {
        _key = key;
        using var aesAlg = new AesCryptoServiceProvider();
        BlockSize = aesAlg.BlockSize;
    }

    public int BlockSize { get; private set; }

    public byte[] EncryptStringToBytes_Aes(string plainText, byte[] iv)
    {
        if (plainText == null || plainText.Length <= 0) throw new ArgumentNullException(nameof(plainText));
        if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));
        byte[] encrypted;


        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
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
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;
    }

    public string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] iv)
    {
        if (cipherText == null || cipherText.Length <= 0) throw new ArgumentNullException(nameof(cipherText));
        if (iv == null || iv.Length <= 0) throw new ArgumentNullException(nameof(iv));

        using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
        {
            aesAlg.Key = _key;
            aesAlg.IV = iv;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;


            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}

/// <summary>
/// A small wrapper to encrypt messages for the API proxy command.
/// See <see cref="HttpCapture.HandleApiRequest"/>
/// </summary>
public class ProxyCipher
{
    private readonly string _keyGen;
    private readonly long _timeStamp;
    private readonly AesCryptoService _cipher;
    private readonly int _blockSizeBytes;
    private readonly byte[] _iv;

    /// <summary>
    /// Create a new proxy-message cipher helper with
    /// a given PRIVATE keyGen, and PUBLIC timeStamp.
    /// </summary>
    public ProxyCipher(string keyGen, string timeStamp)
    {
        // Check general validity
        var tickBytes = Convert.FromBase64String(timeStamp);
        if (tickBytes.Length != 8) throw new Exception("Invalid timestamp");
        _timeStamp = Bit.BytesToInt64Msb(tickBytes);

        Timestamp = timeStamp;
        _keyGen = keyGen;
        _cipher = AesCipher(_keyGen + timeStamp);

        _blockSizeBytes = _cipher.BlockSize / 8;
        _iv = new byte[_blockSizeBytes];
        MixBitsToBits(tickBytes, _iv);
    }

    /// <summary>
    /// Generate and return a timestamp from the current system clock.
    /// </summary>
    public static string TimestampNow => Convert.ToBase64String(Bit.Int64ToBytes(DateTime.UtcNow.Ticks));

    public string Timestamp { get; }

    /// <summary>
    /// Scramble source bytes to dest bytes, changing size as required.
    /// This does NOT add entropy, but just spreads it about.
    /// </summary>
    private static void MixBitsToBits(byte[] source, byte[] dest)
    {
        var max = source.Length > dest.Length ? source.Length : dest.Length;

        dest[0] = (byte)(source[0] ^ source[^1]);
        for (int i = 1; i < max; i++)
        {
            var j = i >> 1;
            var k = max - i;

            var a1 = i % dest.Length; // should be power of 2 in the cases used here
            var a2 = (i - 1) % dest.Length; // should be power of 2 in the cases used here
            var b = j % source.Length;
            var c = k % source.Length;

            dest[a1] = (byte)(dest[a2] ^ source[b] ^ source[c]);
        }
    }

    /// <summary>
    /// Create CBC-mode AES cipher, generating a crypto key from a string keyGen source
    /// </summary>
    private static AesCryptoService AesCipher(string keySource)
    {
        // Hash the secret down to a key
        var key = new byte[32];
        var sourceBytes = Encoding.UTF8.GetBytes(keySource);
        MixBitsToBits(sourceBytes, key);

        return new AesCryptoService(key);

        // build crypto with that key
        /*var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Key = key;
        return aes;*/
    }

    /// <summary>
    /// Returns true if a public key hash is valid given a private keyGen, and the message
    /// timestamp
    /// </summary>
    public bool IsValidCall(string keyHash)
    {
        // Clock drift must be less than one hour
        var remoteClock = new DateTime(_timeStamp, DateTimeKind.Utc);
        var clockDifferenceHours = Math.Abs((DateTime.UtcNow - remoteClock).TotalHours);

        if (clockDifferenceHours > 1.0) return false;

        // Check the key hash
        return MakeKey() == keyHash;
    }

    /// <summary>
    /// Decode an array of bytes into a string.
    /// </summary>
    public string Decode(byte[] bytes)
    {
        if (bytes.Length < _blockSizeBytes) throw new Exception("Invalid incoming data");
        try
        {
            //var plain = _cipher.DecryptCbc(bytes, _iv);
            //return Encoding.UTF8.GetString(plain);
            return _cipher.DecryptStringFromBytes_Aes(bytes, _iv);
        }
        catch (CryptographicException ex)
        {
            throw new Exception("Decoding failed. This is likely a mismatch of keys", ex);
        }
    }

    /// <summary>
    /// Encrypt a string into an array of bytes
    /// </summary>
    public byte[] Encode(string message)
    {
        //var data = Encoding.UTF8.GetBytes(message);
        //return _cipher.EncryptCbc(data, _iv);
        return _cipher.EncryptStringToBytes_Aes(message, _iv);
    }

    /// <summary>
    /// Make a publicly visible message key from the given timestamp and key generator
    /// </summary>
    public string MakeKey()
    {
        var hashKey = Encoding.UTF8.GetBytes(_keyGen);
        var clock = new DateTime(_timeStamp, DateTimeKind.Utc);
        var hashData = Encoding.UTF8.GetBytes(clock.ToString("yyyy-MM-ddTHH:mm:ss"));
        var hashBytes = HMACSHA256.HashData(hashKey, hashData);
        return Convert.ToBase64String(hashBytes);
    }
}