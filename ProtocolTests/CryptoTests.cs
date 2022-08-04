using System.Text;
using NUnit.Framework;
using RawSocketTest;
using RawSocketTest.Crypto;

namespace ProtocolTests;

[TestFixture]
public class CryptoTests
{
    [Test]
    public void esp_round_trip()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var key = RndKey32Byte();
        
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, key.Length * 8);
        var subject = new IkeCrypto(cipher, null, null, key, null, null, null);
        
        // The cipher should pad data out to required size, and remove on decoding.
        // So, any size input data should work.
        var h1 = IpProtocol.MH;
        var plain1 = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");
        
        var h2 = IpProtocol.IPV4;
        var plain2 = Encoding.ASCII.GetBytes("This is a private message. Lorem Ipsum is simply dummy text of the printing and typesetting industry.");
        
        var msg1 = subject.Encrypt(h1, plain1);
        var msg2 = subject.Encrypt(h2, plain2);
        
        // Visual inspection that it was transformed
        Console.WriteLine(Convert.ToBase64String(plain1));
        Console.WriteLine(Convert.ToBase64String(msg1));
        Console.WriteLine();
        Console.WriteLine(Convert.ToBase64String(plain2));
        Console.WriteLine(Convert.ToBase64String(msg2));
        
        var recovered1 = subject.Decrypt(msg1, out var rh1);
        var recovered2 = subject.Decrypt(msg2, out var rh2);
        
        Assert.That(rh1, Is.EqualTo(h1), "header 1 not recovered correctly");
        Assert.That(rh2, Is.EqualTo(h2), "header 2 not recovered correctly");
        
        
        var expected1 = Encoding.ASCII.GetString(plain1);
        var actual1 = Encoding.ASCII.GetString(recovered1);
        Assert.That(actual1, Is.EqualTo(expected1), "First message not recovered");
        
        var expected2 = Encoding.ASCII.GetString(plain2);
        var actual2 = Encoding.ASCII.GetString(recovered2);
        Assert.That(actual2, Is.EqualTo(expected2), "Second message not recovered");
    }

    [Test]
    public void negotiation_round_trip()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var key = RndKey32Byte();
        
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, key.Length * 8);
        var prf = new Prf(PrfId.PRF_HMAC_SHA2_256);
        var iv = RndIv(cipher.BlockSize);
        
        // NOTE: the IVs get updated, so there have to be separate sender and receiver cryptos for negotiation phase
        var subject1 = new IkeCrypto(cipher, null, prf, key, null, null, iv);
        var subject2 = new IkeCrypto(cipher, null, prf, key, null, null, iv);
        
        // The cipher should pad data out to required size, and remove on decoding.
        // So, any size input data should work.
        var plain1 = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");
        
        var plain2 = Encoding.ASCII.GetBytes("This is a private message. Lorem Ipsum is simply dummy text of the printing and typesetting industry.");
        
        var msg1 = subject1.Encrypt1(plain1, 0);
        var msg2 = subject1.Encrypt1(plain2, 1);
        
        // Visual inspection that it was transformed
        Console.WriteLine(Convert.ToBase64String(plain1));
        Console.WriteLine(Convert.ToBase64String(msg1));
        Console.WriteLine();
        Console.WriteLine(Convert.ToBase64String(plain2));
        Console.WriteLine(Convert.ToBase64String(msg2));
        
        var recovered1 = subject2.Decrypt1(msg1, 0, removePad: true);
        var recovered2 = subject2.Decrypt1(msg2, 1, removePad: true);
        
        var expected1 = Encoding.ASCII.GetString(plain1);
        var actual1 = Encoding.ASCII.GetString(recovered1);
        Assert.That(actual1, Is.EqualTo(expected1), "First message not recovered");
        
        var expected2 = Encoding.ASCII.GetString(plain2);
        var actual2 = Encoding.ASCII.GetString(recovered2);
        Assert.That(actual2, Is.EqualTo(expected2), "Second message not recovered");
    }

    [Test]
    public void checksums_dont_break_if_no_algorithm_given()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var key = RndKey32Byte();
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, key.Length * 8);
        
        var subject = new IkeCrypto(cipher, null, null, key, null, null, null);
        
        var plain = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");
        
        var msg = subject.Encrypt(0, plain);
        subject.AddChecksum(msg);
        
        var ok = subject.VerifyChecksum(msg);
        
        Assert.That(ok, Is.True, "checksum");
        
        var recovered = subject.Decrypt(msg, out _);
        
        var expected = Encoding.ASCII.GetString(plain);
        var actual = Encoding.ASCII.GetString(recovered);
        Assert.That(actual, Is.EqualTo(expected), "First message not recovered");
    }
    
    [Test]
    public void checksums_pass_when_data_is_correct()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var mainKey = RndKey32Byte();
        var checksumKey = RndKey32Byte();
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, mainKey.Length * 8);
        var integrity = new Integrity(IntegId.AUTH_HMAC_SHA2_256_128);
        
        var subject = new IkeCrypto(cipher, integrity, null, mainKey, checksumKey, null, null);
        
        var plain = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");
        
        var msg = subject.Encrypt(0, plain);
        subject.AddChecksum(msg);
        
        var ok = subject.VerifyChecksum(msg);
        
        Assert.That(ok, Is.True, "checksum");
        
        var recovered = subject.Decrypt(msg, out _);
        
        var expected = Encoding.ASCII.GetString(plain);
        var actual = Encoding.ASCII.GetString(recovered);
        Assert.That(actual, Is.EqualTo(expected), "First message not recovered");
    }
    
    [Test]
    public void checksums_fail_when_data_is_damaged()
    {
        // for AES-CBC, key must be 16 to 32 bytes, in 8 byte increments
        var mainKey = RndKey32Byte();
        var checksumKey = RndKey32Byte();
        var cipher = new Cipher(EncryptionTypeId.ENCR_AES_CBC, mainKey.Length * 8);
        var integrity = new Integrity(IntegId.AUTH_HMAC_SHA2_256_128);
        
        var subject = new IkeCrypto(cipher, integrity, null, mainKey, checksumKey, null, null);
        
        var plain = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");
        
        var msg = subject.Encrypt(0, plain);
        subject.AddChecksum(msg);
        
        // do some damage
        msg[0] ^= 0x40;
        msg[^1] ^= 0x81;
        
        var ok = subject.VerifyChecksum(msg);
        
        Assert.That(ok, Is.False, "checksum");
    }
    

    private static byte[] RndKey32Byte()
    {
        var key = new byte[32];
        var rnd = new Random();
        rnd.NextBytes(key);
        return key;
    }

    private byte[] RndIv(int cipherBlockSize)
    {
        var key = new byte[cipherBlockSize];
        var rnd = new Random();
        rnd.NextBytes(key);
        return key;
    }
}