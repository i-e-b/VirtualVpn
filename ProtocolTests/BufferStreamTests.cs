using System.Text;
using NUnit.Framework;
using VirtualVpn.PseudoSocket;

namespace ProtocolTests;

[TestFixture]
public class BufferStreamTests
{
    [Test]
    public void buffer_stream_write_and_read()
    {
        var buffer = new byte[1024];
        var subject = new BufferStream();
        
        // Empty behaviour
        Assert.That(subject.AllDataRead, Is.False);
        Assert.That(subject.CanRead, Is.False);
        Assert.That(subject.HasData, Is.False);
        
        var total = subject.Read(buffer, 0, buffer.Length);
        Assert.That(total, Is.Zero);
        
        // Bunch of small fragments
        subject.Write(10, Encoding.ASCII.GetBytes("Hello, "));
        subject.Write(11, Encoding.ASCII.GetBytes("there. "));
        subject.Write(12, Encoding.ASCII.GetBytes("General"));
        subject.Write(13, Encoding.ASCII.GetBytes(" Kenobi"));
        
        Assert.That(subject.AllDataRead, Is.False);
        Assert.That(subject.CanRead, Is.True);
        Assert.That(subject.HasData, Is.True);
        
        buffer[0] = (byte)'<';
        total = subject.Read(buffer, 1, buffer.Length);
        buffer[total+1] = (byte)'>';
        
        Assert.That(total, Is.EqualTo(28));
        
        var result = Encoding.ASCII.GetString(buffer, 0, 30);
        Assert.That(result, Is.EqualTo("<Hello, there. General Kenobi>"));
        
        Assert.That(subject.AllDataRead, Is.False);
        Assert.That(subject.CanRead, Is.False);
        Assert.That(subject.HasData, Is.False);
    }
    
    [Test]
    public void big_frags_small_buffer()
    {
        var buffer = new byte[25];
        var subject = new BufferStream();
        
        subject.Write(1160, Encoding.ASCII.GetBytes("There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words which don't look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isn't anything embarrassing hidden in the middle of text."));

        while (subject.HasData)
        {
            for (int i = 0; i < buffer.Length; i++) { buffer[i] = (byte)'_'; }
            
            var read = subject.Read(buffer, 0, buffer.Length);
            Console.WriteLine(read);
        }
        
        Assert.That(subject.HasData, Is.False);
        Assert.That(subject.CanRead, Is.False);
        
        var result = Encoding.ASCII.GetString(buffer);
        Assert.That(result, Is.EqualTo("le of text.______________"));
    }

    [Test]
    public void out_of_order_writing()
    {
        var buffer = new byte[28];
        var subject = new BufferStream();
        
        var total = subject.Read(buffer, 0, buffer.Length);
        Assert.That(total, Is.Zero);
        
        // Bunch of small fragments
        subject.Write(11, Encoding.ASCII.GetBytes("there. "));
        subject.Write(13, Encoding.ASCII.GetBytes(" Kenobi"));
        subject.Write(10, Encoding.ASCII.GetBytes("Hello, "));
        subject.Write(12, Encoding.ASCII.GetBytes("General"));

        subject.Read(buffer, 0, buffer.Length);
        var result = Encoding.ASCII.GetString(buffer, 0, 28);
        Assert.That(result, Is.EqualTo("Hello, there. General Kenobi"));
    }

    [Test]
    public void stop_on_fragmentation()
    {
        var buffer = new byte[28];
        var subject = new BufferStream();
        
        var total = subject.Read(buffer, 0, buffer.Length);
        Assert.That(total, Is.Zero);
        
        // Bunch of small fragments
        subject.Write(11, Encoding.ASCII.GetBytes("there. "));
        subject.Write(13, Encoding.ASCII.GetBytes(" Kenobi"));
        subject.Write(10, Encoding.ASCII.GetBytes("Hello, "));

        var length = subject.Read(buffer, 0, buffer.Length);
        var result = Encoding.ASCII.GetString(buffer, 0, length);
        
        Assert.That(result, Is.EqualTo("Hello, there. "));
        Assert.That(subject.CanRead, Is.False);
        Assert.That(subject.HasData, Is.True);
    }
    
    [Test]
    public void reading_before_complete()
    {
        // We allow it, but you'll lose anything before the start
        var buffer = new byte[28];
        var subject = new BufferStream();
        
        var total = subject.Read(buffer, 0, buffer.Length);
        Assert.That(total, Is.Zero);
        
        // Bunch of small fragments
        subject.Write(11, Encoding.ASCII.GetBytes("there. "));
        subject.Write(13, Encoding.ASCII.GetBytes(" Kenobi"));
        subject.Write(12, Encoding.ASCII.GetBytes("General"));

        var length = subject.Read(buffer, 0, buffer.Length);
        
        subject.Write(10, Encoding.ASCII.GetBytes("Hello, "));
        
        var result = Encoding.ASCII.GetString(buffer, 0, length);
        Assert.That(result, Is.EqualTo("there. General Kenobi"));
        Assert.That(subject.CanRead, Is.False);
        Assert.That(subject.HasData, Is.True);
    }

    [Test]
    public void complete_flags()
    {
        var buffer = new byte[28];
        var subject = new BufferStream();
        
        var total = subject.Read(buffer, 0, buffer.Length);
        Assert.That(total, Is.Zero);
        
        // Bunch of small fragments
        subject.Write(11, Encoding.ASCII.GetBytes("there. "));
        subject.Write(13, Encoding.ASCII.GetBytes(" Kenobi"));
        subject.SetComplete(13);
        subject.Write(10, Encoding.ASCII.GetBytes("Hello, "));
        subject.Write(12, Encoding.ASCII.GetBytes("General"));
        
        Assert.That(subject.Complete, Is.True);
        Assert.That(subject.CanRead, Is.True);
        Assert.That(subject.HasData, Is.True);
        Assert.That(subject.AllDataRead, Is.False);

        subject.Read(buffer, 0, buffer.Length);
        var result = Encoding.ASCII.GetString(buffer, 0, 28);
        Assert.That(result, Is.EqualTo("Hello, there. General Kenobi"));
        
        Assert.That(subject.Complete, Is.True);
        Assert.That(subject.CanRead, Is.False);
        Assert.That(subject.HasData, Is.False);
        Assert.That(subject.AllDataRead, Is.True);
    }
    
    [Test]
    public void sequence_completion()
    {
        var subject = new BufferStream();
        
        Assert.That(subject.SequenceComplete, Is.False);
        Assert.That(subject.StartSequence, Is.EqualTo(0));
        
        
        subject.Write(11, Encoding.ASCII.GetBytes("there. "));
        Assert.That(subject.SequenceComplete, Is.True);
        Assert.That(subject.StartSequence, Is.EqualTo(11));
        
        subject.Write(13, Encoding.ASCII.GetBytes(" Kenobi"));
        subject.SetComplete(13);
        Assert.That(subject.SequenceComplete, Is.False);
        Assert.That(subject.StartSequence, Is.EqualTo(11));
        
        subject.Write(10, Encoding.ASCII.GetBytes("Hello, "));
        Assert.That(subject.SequenceComplete, Is.False);
        Assert.That(subject.StartSequence, Is.EqualTo(10));
        
        subject.Write(12, Encoding.ASCII.GetBytes("General"));
        Assert.That(subject.SequenceComplete, Is.True);
        Assert.That(subject.StartSequence, Is.EqualTo(10));
    }
}