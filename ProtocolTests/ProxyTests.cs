using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NUnit.Framework;
using SkinnyJson;
using VirtualVpn;
using VirtualVpn.TlsWrappers;
using VirtualVpn.Web;

#pragma warning disable CS8604

namespace ProtocolTests;

[TestFixture]
public class ProxyTests
{
    #region proxy call (API encryption)

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

        const string plainText =
            "No one rejects, dislikes, or avoids pleasure itself, because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that are extremely painful."; // Nerd-cred version of "Lorem ipsum"
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

        var subject = new ProxyCipher(
            "TestApiKeyThatIsAWholeLotLongerThatTheOtherOne.ItShouldBeOver256Bytes.These cases are perfectly simple and easy to distinguish. In a free hour, when our power of choice is untrammelled and when nothing prevents our being able to do what we like best, every|<--256 bytes here| pleasure is to be welcomed and every pain avoided. But in certain circumstances and owing to the claims of duty or the obligations of business it will frequently occur that pleasures have to be repudiated and annoyances accepted.",
            ticks);

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

        var proxyRequest = new HttpProxyRequest
        {
            Headers = { { "Accept", "application/json" }, { "Context-Type", "application/json" } },
            HttpMethod = "POST",
            Body = Encoding.UTF8.GetBytes("Hello proxy")
        };

        var proxyRequestBytes = cipher.Encode(Json.Freeze(proxyRequest));

        var resultBytes = HttpListenerAndApi.HandleProxyCallInternal(keyGen,
            cipher.MakeKey(), timestamp, proxyRequestBytes,
            rq => new HttpProxyResponse
            {
                Headers = { { "Context-Type", "application/json" } },
                StatusCode = 200,
                StatusDescription = rq.HttpMethod + " Done",
                Body = Encoding.UTF8.GetBytes("Hello reality")
            });

        Assert.That(resultBytes, Is.Not.Null, "result bytes");

        var resultString = cipher.Decode(resultBytes);
        Console.WriteLine(resultString);

        var result = Json.Defrost<HttpProxyResponse>(resultString);
        Assert.That(result, Is.Not.Null, "final result");
    }

    #endregion
    
    #region adaptor message reading
    
    [Test]
    public void proxy_call_adaptor_handles_complete_documents()
    {
        Log.SetLevel(LogLevel.Everything);
        var request = new HttpProxyRequest{
            Url = "https://192.168.0.1/what"
        };
        var subject = new TlsHttpProxyCallAdaptor(request, false);

        Assert.That(subject.Connected, Is.True, "Initial state");

        const string doc = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 13\r\n\r\nHello, world!";

        // feed some data in fragments
        var buffer = Encoding.UTF8.GetBytes(doc);
        var read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        
        var endedOk = subject.WaitForFinish(TimeSpan.FromSeconds(1));
        Assert.That(endedOk, Is.True, "clean ending");

        Assert.That(read, Is.EqualTo(buffer.Length), "frag 1 length");
        Assert.That(subject.Connected, Is.False, "should finish at end of document");

        var response = subject.GetResponse();
        Assert.That(response.Success, Is.True, "success flag");
        Assert.That(response.ErrorMessage, Is.Null, "error");
        Assert.That(response.StatusCode, Is.EqualTo(200), "status code");
        Assert.That(response.StatusDescription, Is.EqualTo("OK"), "status message");
        Assert.That(response.Body, Is.Not.Null, "body present");
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("text/plain; charset=utf-8"), "content type");
        Assert.That(response.Headers["Content-Length"], Is.EqualTo("13"), "content length header");

        var bodyString = Encoding.UTF8.GetString(response.Body);
        Assert.That(bodyString, Is.EqualTo("Hello, world!"), "body");
    }

    [Test]
    public void proxy_call_adaptor_handles_fragmented_documents()
    {
        var request = new HttpProxyRequest{
            Url = "https://192.168.0.1/what"
        };
        var subject = new TlsHttpProxyCallAdaptor(request, false);

        Assert.That(subject.Connected, Is.True, "Initial state");

        const string frag1 = "HTTP/1.1 200 OK\r\nContent-Type: ";
        const string frag2 = "text/plain; charset=utf-8\r\nContent-Length: 13\r\n\r\nHel";
        const string frag3 = "lo, world!";

        // feed first fragment
        var buffer = Encoding.UTF8.GetBytes(frag1);
        var read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 1 length");
        Assert.That(subject.Connected, Is.True, "should not finish after frag 1");

        // feed second fragment
        buffer = Encoding.UTF8.GetBytes(frag2);
        read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 2 length");
        Assert.That(subject.Connected, Is.True, "should not finish after frag 2");

        // feed third and final fragment
        buffer = Encoding.UTF8.GetBytes(frag3);
        read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        
        var endedOk = subject.WaitForFinish(TimeSpan.FromSeconds(1));
        Assert.That(endedOk, Is.True, "clean ending");

        Assert.That(read, Is.EqualTo(buffer.Length), "frag 3 length");
        Assert.That(subject.Connected, Is.False, "should finish after frag 3");
        
        // Check that the final output was read correctly
        var response = subject.GetResponse();
        Assert.That(response.Success, Is.True, "success flag");
        Assert.That(response.ErrorMessage, Is.Null, "error");
        Assert.That(response.StatusCode, Is.EqualTo(200), "status code");
        Assert.That(response.StatusDescription, Is.EqualTo("OK"), "status message");
        Assert.That(response.Body, Is.Not.Null, "body present");
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("text/plain; charset=utf-8"), "content type");
        Assert.That(response.Headers["Content-Length"], Is.EqualTo("13"), "content length header");

        var bodyString = Encoding.UTF8.GetString(response.Body);
        Assert.That(bodyString, Is.EqualTo("Hello, world!"), "body");
    }

    [Test]
    public void proxy_call_adaptor_handles_fragmented_chunked_documents()
    {
        var request = new HttpProxyRequest{
            Url = "https://192.168.0.1/what"
        };
        var subject = new TlsHttpProxyCallAdaptor(request, false);

        Assert.That(subject.Connected, Is.True, "Initial state");

        const string frag1 = "HTTP/1.1 200 OK\r\nContent-Type: ";
        const string frag2 = "text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\nPragma:";
        const string frag3 = " no-cache\r\n\r\n5;meta=true\r\nHello\r\n8\r\n, world!\r\n0\r\n\r\n";

        // feed first fragment
        var buffer = Encoding.UTF8.GetBytes(frag1);
        var read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 1 length");
        Assert.That(subject.Connected, Is.True, "should not finish after frag 1");

        // feed second fragment
        buffer = Encoding.UTF8.GetBytes(frag2);
        read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 2 length");
        Assert.That(subject.Connected, Is.True, "should not finish after frag 2");

        // feed third and final fragment
        buffer = Encoding.UTF8.GetBytes(frag3);
        read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        
        var endedOk = subject.WaitForFinish(TimeSpan.FromSeconds(1));
        Assert.That(endedOk, Is.True, "clean ending");

        Assert.That(read, Is.EqualTo(buffer.Length), "frag 3 length");
        Assert.That(subject.Connected, Is.False, "should finish after frag 3");
        
        // Check that the final output was read correctly
        var response = subject.GetResponse();
        Assert.That(response.Success, Is.True, "success flag");
        Assert.That(response.ErrorMessage, Is.Null, "error");
        Assert.That(response.StatusCode, Is.EqualTo(200), "status code");
        Assert.That(response.StatusDescription, Is.EqualTo("OK"), "status message");
        Assert.That(response.Body, Is.Not.Null, "body present");
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("text/plain; charset=utf-8"), "content type");
        Assert.That(response.Headers["Transfer-Encoding"], Is.EqualTo("chunked"), "transfer encoding header");
        Assert.That(response.Headers["Pragma"], Is.EqualTo("no-cache"), "other header");

        var bodyString = Encoding.UTF8.GetString(response.Body);
        Assert.That(bodyString, Is.EqualTo("Hello, world!"), "body");
    }

    [Test]
    public void proxy_call_adaptor_handles_truncated_chunked_documents()
    {
        var request = new HttpProxyRequest{
            Url = "https://192.168.0.1/what"
        };
        var subject = new TlsHttpProxyCallAdaptor(request, false);

        Assert.That(subject.Connected, Is.True, "Initial state");

        const string frag1 = "HTTP/1.1 200 OK\r\nContent-Type: ";
        const string frag2 = "text/plain; charset=utf-8\r\nTransfer-Encoding: chunked\r\nPragma:";
        const string frag3 = " no-cache\r\n\r\n13;meta=true\r\nHello"; // does NOT end correctly

        // feed first fragment
        var buffer = Encoding.UTF8.GetBytes(frag1);
        var read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 1 length");
        Assert.That(subject.Connected, Is.True, "should not finish after frag 1");

        // feed second fragment
        buffer = Encoding.UTF8.GetBytes(frag2);
        read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 2 length");
        Assert.That(subject.Connected, Is.True, "should not finish after frag 2");

        // feed third and final fragment
        buffer = Encoding.UTF8.GetBytes(frag3);
        read = subject.IncomingFromTunnel(buffer, 0, buffer.Length);
        Assert.That(read, Is.EqualTo(buffer.Length), "frag 3 length");
        Assert.That(subject.Connected, Is.True, "should not finish after truncated last fragment");

        // Force the adaptor to close early
        subject.Close();

        // Check that the final output was read correctly
        var response = subject.GetResponse();
        Assert.That(response.Success, Is.False, "success flag");
        Assert.That(response.ErrorMessage, Is.EqualTo("Body was truncated"), "error");
        Assert.That(response.StatusCode, Is.EqualTo(200), "status code");
        Assert.That(response.StatusDescription, Is.EqualTo("OK"), "status message");
        Assert.That(response.Body, Is.Not.Null, "body present");
        Assert.That(response.Headers["Content-Type"], Is.EqualTo("text/plain; charset=utf-8"), "content type");
        Assert.That(response.Headers["Transfer-Encoding"], Is.EqualTo("chunked"), "transfer encoding header");
        Assert.That(response.Headers["Pragma"], Is.EqualTo("no-cache"), "other header");

        var bodyString = Encoding.UTF8.GetString(response.Body);
        Assert.That(bodyString, Is.EqualTo("Hello"), "body");
    }

    [Test]
    public void can_detect_incoming_tls_handshake()
    {
        using var ms = new MemoryStream();
        using var stream = new SslStream(ms, leaveInnerStreamOpen: false, AnyCertificate);
        try
        {
            stream.AuthenticateAsClient("example.com");
        }
        catch (Exception)
        {
            // Ignore-- will fail due to being disconnected
        }
        
        ms.Seek(0, SeekOrigin.Begin);
        var clientHelloMessage = ms.ToArray();
        
        var probablyTls = TlsDetector.IsTlsHandshake(clientHelloMessage, out var acceptableTls);

        Assert.True(probablyTls, "TLS/SSL detection");
        Assert.True(acceptableTls, "version detection");
    }

    [Test]
    public void incoming_tls_handshake_for_pre_tls_protocols_is_flagged_as_unacceptable()
    {
        Log.SetLevel(LogLevel.Everything);
        using var ms = new MemoryStream();
        using var stream = new SslStream(ms, leaveInnerStreamOpen: false, AnyCertificate);
        try
        {
            stream.AuthenticateAsClient("example.com");
        }
        catch (Exception)
        {
            // Ignore-- will fail due to being disconnected
        }
        
        ms.Seek(0, SeekOrigin.Begin);
        var clientHelloMessage = ms.ToArray();
        // dotnet won't allow us to create an obsolete request, so we will hack one in
        clientHelloMessage[2] = 0;
        clientHelloMessage[10] = 0;
        
        var probablyTls = TlsDetector.IsTlsHandshake(clientHelloMessage, out var acceptableTls);

        Assert.True(probablyTls, "TLS/SSL detection");
        Assert.False(acceptableTls, "version detection");
    }
    
    [Test]
    public void tls_check_gives_false_for_incoming_HTTP_message()
    {
        using var ms = new MemoryStream();
        ms.Write(Encoding.UTF8.GetBytes("GET /some/url HTTP/1.1\r\n"));
        
        ms.Seek(0, SeekOrigin.Begin);
        var clientHelloMessage = ms.ToArray();
        
        var probablyTls = TlsDetector.IsTlsHandshake(clientHelloMessage, out var acceptableTls);

        Assert.False(probablyTls, "TLS/SSL detection");
        Assert.False(acceptableTls, "version detection");
    }
    
    [Test]
    public void tls_check_gives_false_for_an_empty_message()
    {
        var probablyTls = TlsDetector.IsTlsHandshake(Array.Empty<byte>(), out var acceptableTls);

        Assert.False(probablyTls, "TLS/SSL detection");
        Assert.False(acceptableTls, "version detection");
    }

    #endregion

    private static bool AnyCertificate(object a, X509Certificate? b, X509Chain? c, SslPolicyErrors d) => true;
}