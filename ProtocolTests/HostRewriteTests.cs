using System.Text;
using NUnit.Framework;
using VirtualVpn.Web;

namespace ProtocolTests;

[TestFixture]
public class HostRewriteTests
{
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