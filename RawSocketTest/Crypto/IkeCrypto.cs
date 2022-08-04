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

    public byte[] DecryptEsp(byte[] encrypted, out byte nextHeader)
    {
        var blockSize = _cipher.BlockSize;
        var hashSize = _integrity?.OutputSize ?? 0;
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

    public byte[] EncryptEsp(byte nextHeader, byte[] plain)
    {
        var blockSize = _cipher.BlockSize;
        var iv = _cipher.GenerateIv();
        var padLength = blockSize - ((plain.Length + 1) % blockSize) - 1;
        
        var pad = new byte[padLength];
        var tail = new[]{(byte)padLength, nextHeader};
        var checksumPad = (_integrity is null) ? Array.Empty<byte>() : new byte[_integrity.OutputSize];
        
        var payload = plain.Concat(pad).Concat(tail).ToArray();
        var encrypted = _cipher.Encrypt(_skE, iv, payload);
        
        var packet = iv.Concat(encrypted).Concat(checksumPad).ToArray();
        
        return packet;
    }
}