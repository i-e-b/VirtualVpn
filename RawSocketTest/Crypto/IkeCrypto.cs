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
    private readonly Dictionary<int,byte[]> _vectors;

    public IkeCrypto(Cipher cipher, Integrity? integrity, Prf? prf, byte[] skE, byte[]? skA, byte[]? skP, byte[]? iv)
    {
        _cipher = cipher;
        _integrity = integrity;
        _prf = prf;
        _skE = skE;
        _skA = skA;
        _skP = skP;
        
        _vectors = new Dictionary<int, byte[]>();
        if (iv is not null) _vectors.Add(0, iv);
        
        _lastIv = null;
    }

    /// <summary>
    /// Recover encrypted data, and the chain byte used
    /// </summary>
    public byte[] Decrypt(byte[] encrypted, out byte nextHeader)
    {
        var blockSize = _cipher.BlockSize;
        var hashSize = _integrity?.HashSize ?? 0;
        var cipherSize = encrypted.Length - blockSize - hashSize;
        
        // encrypted data is [ init vec ][ cipher text ][ checksum ]
        var iv = encrypted.Take(blockSize).ToArray();
        var cipherText = encrypted.Skip(blockSize).Take(cipherSize).ToArray();
        
        // decrypted data is [ message data ][ padding ][ pad len ][ carry-over ]
        var decrypted = _cipher.Decrypt(_skE, iv, cipherText);
        nextHeader = decrypted[^1]; // last element
        var padLength = decrypted[^2]; // second-last element
        var messageBytes = decrypted.Length - padLength - 2;
        
        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Encrypt plain data, using a chain byte
    /// </summary>
    public byte[] Encrypt(byte nextHeader, byte[] plain)
    {
        var blockSize = _cipher.BlockSize;
        var iv = _cipher.GenerateIv();
        var padLength = blockSize - ((plain.Length + 1) % blockSize) - 1;
        
        var pad = new byte[padLength];
        var tail = new[]{(byte)padLength, nextHeader};
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
            if (expected[i] != encrypted[i+payloadLength]) return false;
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
            encrypted[i+payloadLength] = sum[i];
        }
    }
}