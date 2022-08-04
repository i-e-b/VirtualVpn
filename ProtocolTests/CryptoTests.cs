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
        Console.WriteLine(cipher.ValidKeySizes); // describe key sizes
        
        var subject = new IkeCrypto(cipher, null, null, key, null, null, null);
        
        // The cipher should pad data out to required size, and remove on decoding.
        // So, any size input data should work.
        byte h1 = 42;
        var plain1 = Encoding.ASCII.GetBytes("This is a private message, you should not see it in the encrypted text.");
        
        byte h2 = 69;
        var plain2 = Encoding.ASCII.GetBytes("This is a private message. Lorem Ipsum is simply dummy text of the printing and typesetting industry.");
        
        var msg1 = subject.EncryptEsp(h1, plain1);
        var msg2 = subject.EncryptEsp(h2, plain2);
        
        // Visual inspection that it was transformed
        Console.WriteLine(Convert.ToBase64String(plain1));
        Console.WriteLine(Convert.ToBase64String(msg1));
        Console.WriteLine();
        Console.WriteLine(Convert.ToBase64String(plain2));
        Console.WriteLine(Convert.ToBase64String(msg2));
        
        var recovered1 = subject.DecryptEsp(msg1, out var rh1);
        var recovered2 = subject.DecryptEsp(msg2, out var rh2);
        
        Assert.That(rh1, Is.EqualTo(h1), "header 1 not recovered correctly");
        Assert.That(rh2, Is.EqualTo(h2), "header 2 not recovered correctly");
        
        
        var expected1 = Encoding.ASCII.GetString(plain1);
        var actual1 = Encoding.ASCII.GetString(recovered1);
        Assert.That(actual1, Is.EqualTo(expected1), "First message not recovered");
        
        var expected2 = Encoding.ASCII.GetString(plain2);
        var actual2 = Encoding.ASCII.GetString(recovered2);
        Assert.That(actual2, Is.EqualTo(expected2), "Second message not recovered");
    }

    private static byte[] RndKey32Byte()
    {
        var key = new byte[32];
        var rnd = new Random();
        rnd.NextBytes(key);
        return key;
    }
}