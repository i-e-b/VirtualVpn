using System.Text;
using RawSocketTest.Helpers;

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

    public Cipher Cipher => _cipher;
    public Integrity? Integrity => _integrity;
    public Prf? Prf => _prf;
    public byte[] SkA => _skA ?? Array.Empty<byte>();
    public byte[] SkP => _skP ?? Array.Empty<byte>();

    public override string ToString()
    {
        var sb = new StringBuilder();
        
        sb.Append("Cipher: ");
        sb.Append(_cipher);
        sb.AppendLine();

        sb.Append(Bit.Describe("SK_e", _skE));
        sb.Append(Bit.Describe("SK_a", _skA));
        sb.Append(Bit.Describe("SK_p", _skP));
        sb.Append(Bit.Describe("last IV", _lastIv));
        
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
    /// Generate a set of crypto classes given the required data from an IKEv2 session
    /// </summary>
    public static void CreateKeysAndCryptoInstances(
        byte[] theirNonce, byte[] myNonce, byte[] sharedSecret,
        byte[] theirSpi, byte[] mySpi,
        PrfId prfId, IntegId integId, EncryptionTypeId cipherId, int keyLength, byte[]? oldSkD,
        
        out byte[] skD, out IkeCrypto myCrypto, out IkeCrypto theirCrypto
        ){
        // pvpn/server.py:223


        if (Settings.CaptureTraffic)
        {
            File.WriteAllText(Settings.FileBase + "LastSessionKeysSources.txt",
                $"prfId={prfId}, integId={integId}, cipherId={cipherId}, keyLength={keyLength}\r\n" +
                Bit.Describe("theirNonce", theirNonce) +
                Bit.Describe("myNonce", myNonce) +
                Bit.Describe("sharedSecret", sharedSecret) +
                Bit.Describe("theirSpi", theirSpi) +
                Bit.Describe("mySpi", mySpi) +
                Bit.Describe("oldSkD", oldSkD)
            );
        }

        // Build protocols
        var prf = new Prf(prfId);
        var integ = new Integrity(integId);
        var cipher = new Cipher(cipherId, keyLength);
        
        byte[] sKeySeed;
        if (oldSkD is null)
        {
            sKeySeed = prf.Hash(theirNonce.Concat(myNonce).ToArray(), sharedSecret);
        }
        else
        {
            sKeySeed = prf.Hash(oldSkD, sharedSecret.Concat(theirNonce).Concat(myNonce).ToArray());
        }
        
        // Generate crypto bases
        
        var totalSize = 3*prf.KeySize + 2*integ.KeySize + 2*cipher.KeySize;
        var seed = theirNonce.Concat(myNonce).Concat(theirSpi).Concat(mySpi).ToArray();
        var keySource = prf.PrfPlus(sKeySeed, seed, totalSize);
        
        var idx = 0;
        skD = Bit.Subset(prf.KeySize, keySource, ref idx);
        var skAi = Bit.Subset(integ.KeySize, keySource, ref idx);
        var skAr = Bit.Subset(integ.KeySize, keySource, ref idx);
        var skEi = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skEr = Bit.Subset(cipher.KeySize, keySource, ref idx);
        var skPi = Bit.Subset(prf.KeySize, keySource, ref idx);
        var skPr = Bit.Subset(prf.KeySize, keySource, ref idx);
        
        if (idx != keySource.Length) throw new Exception($"Unexpected key set length. Expected {keySource.Length} but got {idx}");
        
        // build crypto for both sides
        myCrypto = new IkeCrypto(cipher, integ, prf, skEr, skAr, skPr, null);
        theirCrypto = new IkeCrypto(cipher, integ, prf, skEi, skAi, skPi, null);

        if (Settings.CaptureTraffic)
        {
            File.WriteAllText(Settings.FileBase + "LastSessionKeys.txt",
                Bit.Describe("peer nonce", theirNonce) +
                Bit.Describe("local nonce", myNonce) +
                Bit.Describe("SK d", skD) +
                Bit.Describe("skAi", skAi) +
                Bit.Describe("skAr", skAr) +
                Bit.Describe("skEi", skEi) +
                Bit.Describe("skEr", skEr) +
                Bit.Describe("skPi", skPi) +
                Bit.Describe("skPr", skPr) +
                Bit.Describe("keySource", keySource) +
                Bit.Describe("seed", seed) +
                Bit.Describe("secret", sharedSecret) +
                Bit.Describe("sKeySeed", sKeySeed)
            );
        }
    }

    /// <summary>
    /// Recover encrypted data. Used for IKE SK payloads
    /// </summary>
    public byte[] Decrypt(byte[] encrypted)
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
        
        // decrypted data is [ message data ][ padding ][ pad len ]
        byte[] decrypted;
        try
        {
            decrypted = _cipher.Decrypt(_skE, iv, cipherText);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to decrypt: {ex}");
            throw;
        }
        
        var padLength = decrypted[^1]; // last byte
        var messageBytes = decrypted.Length - padLength - 1;

        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Encrypt plain data, adding padding for a checksum
    /// </summary>
    public byte[] Encrypt(byte[] plain)
    {
        var blockSize = _cipher.BlockSize;
        var iv = _cipher.GenerateIv();
        var padLength = blockSize - ((plain.Length) % blockSize) - 1;

        var pad = new byte[padLength];
        var tail = new[] { (byte)padLength };
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

        var idx = 0;
        var shorter = Bit.Subset(encrypted.Length - _integrity.HashSize, encrypted, ref idx);

        return VerifyChecksumInternal(shorter, target);
    }

    private bool VerifyChecksumInternal(byte[] encrypted, byte[] target)
    {
        // compute
        var expected = _integrity!.Compute(_skA!, encrypted);
        
        Log.Debug($"    Comparing checksums: {Hex(expected)} == {Hex(target)} ? sk-A={Hex(_skA!)}");
        
        // compare
        for (int i = 0; i < expected.Length; i++)
        {
            if (expected[i] != target[i]) return false;
        }
        
        return true;
    }

    private static string Hex(IEnumerable<byte> expected) => string.Join("", expected.Select(v=>v.ToString("x2")));

    /// <summary>
    /// Calculate and inject a checksum into an encrypted message.
    /// "assoc" comes from the header of the IkeMessage, not including encrypted data or SPE zero padding
    /// </summary>
    public void AddChecksum(byte[] encrypted, byte[] assoc)
    { 
/* prepare data to authenticate-decrypt:
 * | IV | plain | padding | ICV |
 *       \____crypt______/   ^
 *              |           /
 *              v          /
 *     assoc -> + ------->/
 *
 * "assoc" looks like
 *    0: A1 33 E4 06 B4 C3 17 10 33 52 09 94 0F 58 36 87
 *   16: 2E 20 23 20 00 00 00 01 00 00 00 B0 21 00 00 94
 */
        
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
    /// Calculate a checksum, return checksum bytes without changing incoming data
    /// </summary>
    public byte[] CalculateChecksum(byte[] message)
    {
        if (_integrity is null) return Array.Empty<byte>();
        if (_skA is null) throw new Exception($"Checksum is present, but no checksum key was given ({nameof(_skA)})");

        // read just the main body
        var payloadLength = message.Length - _integrity.HashSize;
        var mainPayload = message.Take(payloadLength).ToArray();

        // compute
        return _integrity.Compute(_skA, mainPayload);
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

    /// <summary>
    /// Decode an Encapsulating Security Payload (ESP) packet. This should give us details of what kind of protocol is encapsulated
    /// </summary>
    public byte[] DecryptEsp(byte[] encrypted, out IpProtocol next)
    {
        // pvpn/crypto.py:81
        
        var initVectorSize = _cipher.BlockSize;
        var hashSize = _integrity?.HashSize ?? 0;
        var cipherSize = encrypted.Length - initVectorSize - hashSize;
        
        Log.Crypto($"IV={initVectorSize} bytes; Hash={hashSize} bytes; Cipher={cipherSize} bytes;");
        
        // encrypted data is [ init vec ][ cipher text ][ checksum ]
        var iv = encrypted.Take(initVectorSize).ToArray();
        var cipherText = encrypted.Skip(initVectorSize).Take(cipherSize).ToArray();
        
        // decrypted data is [ message data ][ padding ][ pad len ][ protocol ]
        byte[] decrypted;
        try
        {
            decrypted = _cipher.Decrypt(_skE, iv, cipherText);
        }
        catch (Exception ex)
        {
            Log.Error($"Failed to decrypt: {ex}");
            throw;
        }
        
        var padLength = decrypted[^2]; // second last byte
        if (padLength > decrypted.Length - 2) throw new Exception($"Invalid decryption: Padding length exceeded message length: Pad={padLength} bytes, Plaintext length={decrypted.Length} bytes");
        
        next = (IpProtocol)decrypted[^1]; // second last byte
        var messageBytes = decrypted.Length - padLength - 2;

        Log.Crypto($"Decoded={decrypted.Length} bytes; Pad={padLength} bytes; Protocol={next.ToString()}; Message={messageBytes} bytes;");
        
        return decrypted.Take(messageBytes).ToArray();
    }

    /// <summary>
    /// Output all keys to a string
    /// </summary>
    public string UnsafeDump()
    {
        var sb = new StringBuilder();
        
        sb.Append(Bit.Describe("skE", _skE));
        sb.Append(Bit.Describe("skA", _skA));
        sb.Append(Bit.Describe("skP", _skP));
        sb.Append(Bit.Describe("lastIv", _lastIv));

        foreach (var vector in _vectors)
        {
            sb.Append(Bit.Describe($"vector_{vector.Key}", vector.Value));
        }
        
        return sb.ToString();
    }
}