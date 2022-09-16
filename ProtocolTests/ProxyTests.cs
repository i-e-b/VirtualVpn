using System.Text;
using NUnit.Framework;
using SkinnyJson;
using VirtualVpn.Web;
#pragma warning disable CS8604

namespace ProtocolTests;

[TestFixture]
public class ProxyTests
{
    [Test]
    public void generate_a_proxy_cipher()
    {
        var ticks = ProxyCipher.TimestampNow;
        
        var subject = new ProxyCipher("TestApiKey", ticks);
        
        Assert.That(subject, Is.Not.Null);
    }

    [Test]
    public void can_encrypt_and_decrypt_data_given_the_same_keys()
    {
        var ticks = ProxyCipher.TimestampNow;
        
        var subject = new ProxyCipher("TestApiKey", ticks);
        
        const string plainText = "No one rejects, dislikes, or avoids pleasure itself, because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that are extremely painful."; // Nerd-cred version of "Lorem ipsum"
        var cipherText = subject.Encode(plainText);
        
        var check = Encoding.Unicode.GetString(cipherText);
        Console.WriteLine(check);
        Assert.That(check, Is.Not.EqualTo(plainText));
        
        var recovered = subject.Decode(cipherText);
        Assert.That(recovered, Is.EqualTo(plainText));
    }
    
    [Test]
    public void can_encrypt_and_decrypt_with_long_keys_and_short_data()
    {
        var ticks = ProxyCipher.TimestampNow;
        
        var subject = new ProxyCipher("TestApiKeyThatIsAWholeLotLongerThatTheOtherOne.ItShouldBeOver256Bytes.These cases are perfectly simple and easy to distinguish. In a free hour, when our power of choice is untrammelled and when nothing prevents our being able to do what we like best, every|<--256 bytes here| pleasure is to be welcomed and every pain avoided. But in certain circumstances and owing to the claims of duty or the obligations of business it will frequently occur that pleasures have to be repudiated and annoyances accepted.", ticks);
        
        const string plainText = "short";
        var cipherText = subject.Encode(plainText);
        
        var check = Encoding.Unicode.GetString(cipherText);
        Console.WriteLine(check);
        Assert.That(check, Is.Not.EqualTo(plainText));
        
        var recovered = subject.Decode(cipherText);
        Assert.That(recovered, Is.EqualTo(plainText));
    }
    
    [Test]
    public void decryption_fails_if_the_wrong_timestamp_is_used()
    {
        var ticks = ProxyCipher.TimestampNow;
        var encoder = new ProxyCipher("TestApiKey", ticks);
        
        const string plainText = "The wise man therefore always holds in these matters to this principle of selection: he rejects pleasures to secure other greater pleasures, or else he endures pains to avoid worse pains.";
        var cipherText = encoder.Encode(plainText);
        
        var check = Encoding.Unicode.GetString(cipherText);
        Console.WriteLine(check);
        Assert.That(check, Is.Not.EqualTo(plainText));

        var decoder = new ProxyCipher("TestApiKey", ProxyCipher.TimestampNow); // Assumes the system clock resolution is enough to have ticked again by now
        Assert.Throws<Exception>(() => decoder.Decode(cipherText));
    }
    
    [Test]
    public void decryption_fails_if_the_wrong_key_is_used()
    {
        var ticks = ProxyCipher.TimestampNow;
        var encoder = new ProxyCipher("TestApiKey", ticks);
        
        const string plainText = "The wise man therefore always holds in these matters to this principle of selection: he rejects pleasures to secure other greater pleasures, or else he endures pains to avoid worse pains.";
        var cipherText = encoder.Encode(plainText);
        
        var check = Encoding.Unicode.GetString(cipherText);
        Console.WriteLine(check);
        Assert.That(check, Is.Not.EqualTo(plainText));


        var decoder = new ProxyCipher("TestApiKex", ticks); // slight change should cause complete failure
        Assert.Throws<Exception>(() => decoder.Decode(cipherText));
    }

    [Test]
    public void the_proxy_handler_deals_with_encryption_correctly()
    {
        var keyGen = "TestCryptoKeySource";
        var timestamp = ProxyCipher.TimestampNow;
        var cipher = new ProxyCipher(keyGen, timestamp);
        
        var proxyRequest = new ProxyRequest
        {
            Headers = { { "Accept", "application/json" }, {"Context-Type", "application/json"} },
            HttpMethod = "POST",
            Body = Encoding.UTF8.GetBytes("Hello proxy")
        };
        
        var proxyRequestBytes = cipher.Encode(Json.Freeze(proxyRequest));
        
        var resultBytes = HttpCapture.HandleProxyCallInternal(keyGen,
            cipher.MakeKey(), timestamp, proxyRequestBytes,
            rq => new ProxyResponse
            {
                Headers = { {"Context-Type", "application/json"} },
                StatusCode = 200,
                StatusDescription = rq.HttpMethod + " Done",
                Body = Encoding.UTF8.GetBytes("Hello reality")
            });
        
        Assert.That(resultBytes, Is.Not.Null, "result bytes");
        
        var resultString = cipher.Decode(resultBytes);
        Console.WriteLine(resultString);
        
        var result = Json.Defrost<ProxyResponse>(resultString);
        Assert.That(result, Is.Not.Null, "final result");
    }
}