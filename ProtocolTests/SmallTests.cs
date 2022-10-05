using System.Text;
using NUnit.Framework;
using VirtualVpn;
using VirtualVpn.InternetProtocol;
using VirtualVpn.Web;

namespace ProtocolTests;

[TestFixture]
public class SmallTests
{
    [Test]
    public void enum_ordering_works()
    {
        Assert.True(LogLevel.Trace < LogLevel.Crypto, "enum order");
    }

    [Test]
    public void ipv4_describe_works()
    {
        var result = IpV4Address.Describe(0x12345678);
        Assert.That(result, Is.EqualTo("18.52.86.120"));
    }

    [Test]
    public void byte_search()
    {
        var needle = new byte[] { 50, 60, 40 };

        int i;
        Assert.True(HttpHostHeaderRewriter.Contains(needle, needle, out i), "self");
        Assert.That(i, Is.EqualTo(0));

        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 50, 60, 40 },
            needle, out i), "offset 1, end");
        Assert.That(i, Is.EqualTo(1));

        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 50, 60, 40, 10 },
            needle, out i), "offset 2, start");
        Assert.That(i, Is.EqualTo(0));

        Assert.False(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 50, 30, 40, 20, 60, 40, 10 },
            needle, out i), "mix 1");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 50, 30, 40, 20, 50, 60, 40, 10 },
            needle, out i), "mix 2");
        Assert.That(i, Is.EqualTo(6));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 30, 30, 40, 20, 50, 60, 40, 10 },
            needle, out i), "mix 3");
        Assert.That(i, Is.EqualTo(6));
        
        Assert.False(HttpHostHeaderRewriter.Contains(
            new byte[] { 10, 20, 30, 30, 40, 20, 50, 61, 40, 10 },
            needle, out i), "mix 4");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            new byte[] { 50, 60, 50, 60, 50, 60, 50, 60, 40, 50, 60 },
            needle, out i), "mix 5");
        Assert.That(i, Is.EqualTo(6));
    }
    
    [Test]
    public void byte_search_2()
    {
            // ReSharper disable StringLiteralTypo
        var needle = Encoding.ASCII.GetBytes("world");

        Assert.True(HttpHostHeaderRewriter.Contains(needle, needle, out var i), "self");
        Assert.That(i, Is.EqualTo(0));

        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("wxrlddddworld"),
            needle, out i), "offset 1, end");
        Assert.That(i, Is.EqualTo(8));

        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("worldddddddd"),
            needle, out i), "offset 2, start");
        Assert.That(i, Is.EqualTo(0));

        Assert.False(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("hello, wold warld weird"),
            needle, out i), "mix 1");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("rldwoldworldwordworl"),
            needle, out i), "mix 2");
        Assert.That(i, Is.EqualTo(7));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("dlorwdlorwdloworldrwdlorwdlorw"),
            needle, out i), "mix 3");
        Assert.That(i, Is.EqualTo(13));
        
        Assert.False(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("dlorwdlorwdlorwdlorwdlorw"),
            needle, out i), "mix 4");
        Assert.That(i, Is.EqualTo(-1));
        
        Assert.True(HttpHostHeaderRewriter.Contains(
            Encoding.ASCII.GetBytes("Hello, world"),
            needle, out i), "mix 5");
        Assert.That(i, Is.EqualTo(7));
            // ReSharper restore StringLiteralTypo
    }

    [Test]
    public void host_writer_test()
    {
        var subject = new HttpHostHeaderRewriter("my-host.example.com");
        
        var buffer = Encoding.ASCII.GetBytes("POST /some/path/somewhere HTTP/1.1\r\nAccept: */*\r\nHost: wrong-site.example.org\r\nX-Other-Head: fishes\r\n\r\nblah\r\n");
        
        var offset = 0;
        var length = buffer.Length;
        
        var newBuffer = subject.Process(buffer, ref offset, ref length);
        
        var outcome = Encoding.ASCII.GetString(newBuffer);
        Console.WriteLine(outcome);
        Assert.That(outcome, Is.EqualTo("POST /some/path/somewhere HTTP/1.1\r\nAccept: */*\r\nHost: my-host.example.com\r\nX-Other-Head: fishes\r\n\r\nblah\r\n"));
    }
    
    [Test]
    public void host_writer_test_with_offsets()
    {
        var subject = new HttpHostHeaderRewriter("my-host.example.com");
        
        var buffer = Encoding.ASCII.GetBytes("NO-WAY?NO-WAY!POST /some/path/somewhere HTTP/1.1\r\nAccept: */*\r\nHost: wrong-site.example.org\r\nX-Other-Head: fishes\r\n\r\nblah\r\nNO-WAY?NO-WAY!");
        
        var offset = 14;
        var length = 109;
        
        var newBuffer = subject.Process(buffer, ref offset, ref length);
        
        var outcome = Encoding.ASCII.GetString(newBuffer);
        Console.WriteLine(outcome);
        Assert.That(outcome, Is.EqualTo("POST /some/path/somewhere HTTP/1.1\r\nAccept: */*\r\nHost: my-host.example.com\r\nX-Other-Head: fishes\r\n\r\nblah\r\n"));
    }
    
    [Test]
    public void host_writer_test_partial()
    {
        var subject = new HttpHostHeaderRewriter("my-host.example.com");
        
        var buffer1 = Encoding.ASCII.GetBytes("POST /some/path/somewhere HTTP/1.1" +
                                              "\r\nAccept: */*\r\nHos");
        var buffer2 =                       Encoding.ASCII.GetBytes("t: wrong-site.exam");
        var buffer3 =                                         Encoding.ASCII.GetBytes("ple.org\r\nX-Other-Head: fishes\r\n\r\nblah\r\n");
        
        // Feed the chunks in. The re-writer is allowed to buffer up the headers,
        // but should try to send data out each time. No buffering should happen
        // once the header is re-written.
        
        var result = new List<byte>();
        var offset = 0;
        
        var length = buffer1.Length;
        var newBuffer = subject.Process(buffer1, ref offset, ref length);
        result.AddRange(newBuffer.Skip(offset).Take(length));
        
        length = buffer2.Length;
        newBuffer = subject.Process(buffer2, ref offset, ref length);
        result.AddRange(newBuffer.Skip(offset).Take(length));
        
        length = buffer3.Length;
        newBuffer = subject.Process(buffer3, ref offset, ref length);
        result.AddRange(newBuffer.Skip(offset).Take(length));
        
        var outcome = Encoding.ASCII.GetString(result.ToArray());
        Console.WriteLine(outcome);
        Assert.That(outcome, Is.EqualTo("POST /some/path/somewhere HTTP/1.1\r\nAccept: */*\r\nHost: my-host.example.com\r\nX-Other-Head: fishes\r\n\r\nblah\r\n"));
    }
    
    [Test]
    public void host_writer_test_partial_with_tail()
    {
        var subject = new HttpHostHeaderRewriter("my-host.example.com");
        
        var buffer1 = Encoding.ASCII.GetBytes("POST /some/path/somewhere HTTP/1.1");
        var buffer2 = Encoding.ASCII.GetBytes("\r\nAccept: */*\r\nHost: wrong-site.example.org\r\n");
        var buffer3 = Encoding.ASCII.GetBytes("X-Other-Head: fishes\r\n\r\nblah\r\n");
        
        // Feed the chunks in. The re-writer is allowed to buffer up the headers,
        // but should try to send data out each time. No buffering should happen
        // once the header is re-written.
        
        var result = new List<byte>();
        var offset = 0;
        
        var length = buffer1.Length;
        var newBuffer = subject.Process(buffer1, ref offset, ref length);
        result.AddRange(newBuffer.Skip(offset).Take(length));
        
        length = buffer2.Length;
        newBuffer = subject.Process(buffer2, ref offset, ref length);
        result.AddRange(newBuffer.Skip(offset).Take(length));
        
        length = buffer3.Length;
        newBuffer = subject.Process(buffer3, ref offset, ref length);
        result.AddRange(newBuffer.Skip(offset).Take(length));
        
        var outcome = Encoding.ASCII.GetString(result.ToArray());
        Console.WriteLine(outcome);
        Assert.That(outcome, Is.EqualTo("POST /some/path/somewhere HTTP/1.1\r\nAccept: */*\r\nHost: my-host.example.com\r\nX-Other-Head: fishes\r\n\r\nblah\r\n"));
    }
}