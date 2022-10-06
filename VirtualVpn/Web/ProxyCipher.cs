using System.Security.Cryptography;
using System.Text;

namespace VirtualVpn.Web;

/// <summary>
/// A small wrapper to encrypt messages for the API proxy command.
/// See <see cref="HttpListenerAndApi.HandleApiRequest"/>
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
        _timeStamp = BytesToInt64Msb(tickBytes);

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
    public static string TimestampNow => Convert.ToBase64String(Int64ToBytes(DateTime.UtcNow.Ticks));

    /// <summary>
    /// Get the timestamp value with which this cipher was created
    /// </summary>
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
            return _cipher.DecryptStringFromBytes(bytes, _iv);
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
        return _cipher.EncryptStringToBytes(message, _iv);
    }

    /// <summary>
    /// Make a publicly visible message key from the given timestamp and key generator
    /// </summary>
    public string MakeKey()
    {
        var hashKey = Encoding.UTF8.GetBytes(_keyGen);
        var clock = new DateTime(_timeStamp, DateTimeKind.Utc);
        var hashData = Encoding.UTF8.GetBytes(clock.ToString("yyyy-MM-ddTHH:mm:ss"));
        var hashBytes = AesCryptoService.HashData(hashKey, hashData);
        return Convert.ToBase64String(hashBytes);
    }
    
    /// <summary>
    /// Convert a 64-bit int to 8 bytes in an array.
    /// </summary>
    private static byte[] Int64ToBytes(long value)
    {
        var data = new byte[8];
        
        data[0] = (byte)((value >> 56) & 0xff);
        data[1] = (byte)((value >> 48) & 0xff);
        data[2] = (byte)((value >> 40) & 0xff);
        data[3] = (byte)((value >> 32) & 0xff);
        
        data[4] = (byte)((value >> 24) & 0xff);
        data[5] = (byte)((value >> 16) & 0xff);
        data[6] = (byte)((value >>  8) & 0xff);
        data[7] = (byte)((value >>  0) & 0xff);
        
        return data;
    }
    
    /// <summary>
    /// Read most significant bytes first from data, filling in
    /// as much of a 64-bit integer as possible,
    /// starting at most significant byte of output.
    /// Will stop after 8 bytes, OR if data is exhausted.
    /// </summary>
    private static long BytesToInt64Msb(byte[] data)
    {
        var result = 0L;
        var idx = 0;
        var end = data.Length;
        result |= (long)data[idx++] << 56;
        if (idx >= end) return result;
        result |= (long)data[idx++] << 48;
        if (idx >= end) return result;
        result |= (long)data[idx++] << 40;
        if (idx >= end) return result;
        result |= (long)data[idx++] << 32;
        if (idx >= end) return result;
        
        result |= (long)data[idx++] << 24;
        if (idx >= end) return result;
        result |= (long)data[idx++] << 16;
        if (idx >= end) return result;
        result |= (long)data[idx++] <<  8;
        if (idx >= end) return result;
        result |= (long)data[idx  ] <<  0;
        return result;
    }
}