using System.Text;

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
    private readonly Dictionary<uint, byte[]> _vectors;


    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append("Cipher: ");
        sb.Append(_cipher);

        if (_integrity is null)
        {
            sb.Append(" no checksum present.");
        }
        else
        {
            sb.Append(" Checksum: ");
            sb.Append(_integrity);
        }


        if (_prf is null)
        {
            sb.Append(" no random function present.");
        }
        else
        {
            sb.Append(" Random: ");
            sb.Append(_prf);
        }

        return sb.ToString();
    }

    public IkeCrypto(Cipher cipher, Integrity? integrity, Prf? prf, byte[] skE, byte[]? skA, byte[]? skP, byte[]? iv)
    {
        _cipher = cipher;
        _integrity = integrity;
        _prf = prf;
        _skE = skE;
        _skA = skA;
        _skP = skP;

        _vectors = new Dictionary<uint, byte[]>();
        if (iv is not null) _vectors.Add(0, iv);

        _lastIv = null;
    }

    /// <summary>
    /// Recover encrypted data, and the chain byte used
    /// </summary>
    public byte[] Decrypt(byte[] encrypted, out IpProtocol nextHeader)
    {
        /*
                               1                   2                   3
           0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
          !                     Initialization Vector                     !
          !         (length is block size for encryption algorithm)       !
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     <--+
          !                    Encrypted IKE Payloads                     !        |
          +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        |
          !               !             Padding (0-255 octets)            !       This is cipher input data
          +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+        |
          !                                               !  Pad Length   !        |
          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     <--+
    */
        
        var initVectorSize = _cipher.BlockSize;
        var hashSize = _integrity?.HashSize ?? 0;
        var cipherSize = encrypted.Length - initVectorSize - hashSize;
        
        // encrypted data is [ init vec ][ cipher text ][ checksum ]
        var iv = encrypted.Take(initVectorSize).ToArray();
        var cipherText = encrypted.Skip(initVectorSize).Take(cipherSize).ToArray();

        /* prepare data to authenticate-decrypt:
         * | IV | plain | padding | ICV |
         *       \____crypt______/   ^
         *              |           /
         *              v          /
         *     assoc -> + ------->/
         */
        
        // decrypted data is [ message data ][ padding ][ pad len ][ carry-over ]
        byte[] decrypted;
        try
        {
            decrypted = _cipher.Decrypt(_skE, iv, cipherText);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to decrypt: {ex}");
            throw;
        }

        nextHeader = (IpProtocol)decrypted[^1]; // last element
        var padLength = decrypted[^2]; // second-last element
        var messageBytes = decrypted.Length - padLength - 2;

        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Encrypt plain data, using a chain byte
    /// </summary>
    public byte[] Encrypt(IpProtocol nextHeader, byte[] plain)
    {
        var blockSize = _cipher.BlockSize;
        var iv = _cipher.GenerateIv();
        var padLength = blockSize - ((plain.Length + 1) % blockSize) - 1;

        var pad = new byte[padLength];
        var tail = new[] { (byte)padLength, (byte)nextHeader };
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

        var cxBase = encrypted.Length - _integrity.HashSize;
        var target = Bit.Subset(_integrity.HashSize, encrypted, ref cxBase);
        
        var result = false;
        var chop = 0;
        while (!result)
        {
            var idx = 4;
            if (chop + idx >= encrypted.Length) break;
            
            var shorter = Bit.Subset(encrypted.Length - chop - idx, encrypted, ref idx);
            var longer = new byte[4].Concat(shorter).ToArray();

            result = VerifyChecksumInternal(shorter, target);
            result |= VerifyChecksumInternal(longer, target);
            
            chop ++;
        }
        return result;
    }

    private bool VerifyChecksumInternal(byte[] encrypted, byte[] target)
    {
        // compute
        var expected = _integrity!.Compute(_skA!, encrypted);
        
        Console.WriteLine($"    Comparing checksums: {Hex(expected)} == {Hex(target)} ? sk-A={Hex(_skA!)}");
        
        // compare
        for (int i = 0; i < expected.Length; i++)
        {
            if (expected[i] != target[i]) return false;
        }
        
        return true;
    }

    private static string Hex(IEnumerable<byte> expected) => string.Join("", expected.Select(v=>v.ToString("x2")));

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
            encrypted[i + payloadLength] = sum[i];
        }
    }

    /// <summary>
    /// Decrypt data from negotiation phase (phase 2?)
    /// </summary>
    public byte[] Decrypt1(byte[] encrypted, uint messageId, bool removePad = false)
    {
        // get initialisation vector
        EnsureInitVector(messageId);
        var iv = _vectors[messageId];

        // decrypt message
        var decrypted = _cipher.Decrypt(_skE, iv, encrypted);

        // update IV
        var mainMessage = encrypted.Length - _cipher.BlockSize;
        _vectors[messageId] = encrypted.Skip(mainMessage).ToArray();

        // By the spec, we should remove padding from `plain` here, but
        // source material says "do not remove padding according to ios cisco ipsec bug" (see pvpn/crypto.py:108 )
        if (!removePad) return decrypted;

        // remove padding
        var padLength = decrypted[^1]; // second-last element
        var messageBytes = decrypted.Length - padLength - 1;

        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Encrypt data from negotiation phase (phase 2?)
    /// </summary>
    public byte[] Encrypt1(byte[] plain, uint messageId)
    {
        // get initialisation vector
        EnsureInitVector(messageId);
        var iv = _vectors[messageId];

        // pad message to block size, with space for padding length byte. 
        var blockSize = _cipher.BlockSize;
        var padLength = blockSize - ((plain.Length + 1) % blockSize);

        var pad = new byte[padLength];
        var tail = new[] { (byte)padLength };

        var payload = plain.Concat(pad).Concat(tail).ToArray();

        // encrypt the payload
        var encrypted = _cipher.Encrypt(_skE, iv, payload);

        // update IV
        var mainMessage = encrypted.Length - _cipher.BlockSize;
        _vectors[messageId] = encrypted.Skip(mainMessage).ToArray();

        return encrypted;
    }

    /// <summary>
    /// Make sure we have enough data and algorithms set to read an IV.
    /// Throws if not possible.
    /// </summary>
    private void EnsureInitVector(uint messageId)
    {
        if (_prf is null) throw new Exception("Hash function (PRF) has not been agreed");
        if (!_vectors.ContainsKey(0)) throw new Exception("First initialisation vector has not been set");

        // make sure we have an iv
        if (!_vectors.ContainsKey(messageId))
        {
            var blockSize = _cipher.BlockSize;
            var src = _vectors[0].Concat(Bit.UInt32ToBytes(messageId)).ToArray();
            var fullHash = _prf.Hash(_skE, src);
            var slice = fullHash.Length == blockSize ? fullHash : fullHash.Take(blockSize).ToArray();
            _vectors.Add(messageId, slice);
        }
    }

    // TODO: move this stuff into its own class? ...
}