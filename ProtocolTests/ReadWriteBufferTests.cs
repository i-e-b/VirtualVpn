using NUnit.Framework;
using VirtualVpn.TcpProtocol;

namespace ProtocolTests;

[TestFixture]
public class ReadWriteBufferTests
{
    [Test]
    public void can_write_and_read_from_the_read_buffer_in_chunks()
    {
        var subject = new ReceiveBuffer();
        
        // Simple ordered chunks
        subject.Insert(Seg(420, new byte[]{1,2,3,4,5,6,7,8,9,10}));
        subject.Insert(Seg(430, new byte[]{11,12,13,14,15,16,17,18,19,20}));
        subject.Insert(Seg(440, new byte[]{21,22,23,24,25,26,27,28,29,30}));
        Assert.That(subject.RemainingData(), Is.EqualTo(30), "remains");
        
        // Read back in same size chunks
        var buffer = new byte[10];
        
        var actual = subject.ReadOutAndUpdate(buffer,0,10);
        Assert.That(actual, Is.EqualTo(10), "length");
        Assert.That(buffer, Is.EqualTo(new byte[]{1,2,3,4,5,6,7,8,9,10}).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(20), "remains");
        
        
        actual = subject.ReadOutAndUpdate(buffer,0,10);
        Assert.That(actual, Is.EqualTo(10), "length");
        Assert.That(buffer, Is.EqualTo(new byte[]{11,12,13,14,15,16,17,18,19,20}).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(10), "remains");
        
        
        actual = subject.ReadOutAndUpdate(buffer,0,10);
        Assert.That(actual, Is.EqualTo(10), "length");
        Assert.That(buffer, Is.EqualTo(new byte[]{21,22,23,24,25,26,27,28,29,30}).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(0), "remains");
        
        
        // Should now be empty. Try final read to get zero
        actual = subject.ReadOutAndUpdate(buffer,0,10);
        Assert.That(actual, Is.Zero, "length");
    }
    
    [Test]
    public void can_write_and_read_from_the_read_buffer_in_small_chunks()
    {
        var subject = new ReceiveBuffer();
        
        // Simple ordered chunks
        subject.Insert(Seg(420, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }));
        subject.Insert(Seg(430, new byte[] { 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 }));
        subject.Insert(Seg(440, new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 }));
        Assert.That(subject.RemainingData(), Is.EqualTo(30), "remains");
        

        // Read back in chunks smaller than original (length co-prime, so we don't end up aligned anyway)
        var buffer = new byte[7];

        var actual = subject.ReadOutAndUpdate(buffer, 0, 7);
        Assert.That(actual, Is.EqualTo(7), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 1, 2, 3, 4, 5, 6, 7 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(23), "remains");


        actual = subject.ReadOutAndUpdate(buffer, 0, 7);
        Assert.That(actual, Is.EqualTo(7), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 8, 9, 10, 11, 12, 13, 14 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(16), "remains");


        actual = subject.ReadOutAndUpdate(buffer, 0, 7);
        Assert.That(actual, Is.EqualTo(7), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 15, 16, 17, 18, 19, 20, 21 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(9), "remains");


        actual = subject.ReadOutAndUpdate(buffer, 0, 7);
        Assert.That(actual, Is.EqualTo(7), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 22, 23, 24, 25, 26, 27, 28 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(2), "remains");


        Clear(buffer);
        actual = subject.ReadOutAndUpdate(buffer, 0, 7);
        Assert.That(actual, Is.EqualTo(2), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 29, 30   ,0,0,0,0,0}).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(0), "remains");
        
        
        // Should now be empty. Try final read to get zero
        actual = subject.ReadOutAndUpdate(buffer,0,10);
        Assert.That(actual, Is.Zero, "length");
    }
    
        
    [Test]
    public void can_write_and_read_from_the_read_buffer_in_large_chunks()
    {
        var subject = new ReceiveBuffer();
        
        // Simple ordered chunks
        subject.Insert(Seg(420, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }));
        subject.Insert(Seg(430, new byte[] { 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 }));
        subject.Insert(Seg(440, new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 }));
        Assert.That(subject.RemainingData(), Is.EqualTo(30), "remains");

        // Read back in chunks larger than original
        var buffer = new byte[12];

        var actual = subject.ReadOutAndUpdate(buffer, 0, 12);
        Assert.That(actual, Is.EqualTo(12), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(18), "remains");
        
        actual = subject.ReadOutAndUpdate(buffer, 0, 12);
        Assert.That(actual, Is.EqualTo(12), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(6), "remains");
        
        Clear(buffer);
        actual = subject.ReadOutAndUpdate(buffer, 0, 12);
        Assert.That(actual, Is.EqualTo(6), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 25, 26, 27, 28, 29, 30, 0, 0, 0, 0, 0, 0 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(0), "remains");
        
        
        // Should now be empty. Try final read to get zero
        actual = subject.ReadOutAndUpdate(buffer,0,10);
        Assert.That(actual, Is.Zero, "length");
    }

    private void Clear(byte[] buffer) { for (int i = 0; i < buffer.Length; i++) { buffer[i]=0; } }

    private TcpSegment Seg(int seq, byte[] data)
    {
        return new TcpSegment
        {
            SourcePort = 0,
            DestinationPort = 0,
            SequenceNumber = seq,
            AcknowledgmentNumber = 0,
            DataOffset = 0,
            Reserved = 0,
            Flags = TcpSegmentFlags.None,
            WindowSize = 0,
            Checksum = 0,
            UrgentPointer = 0,
            Options = Array.Empty<byte>(),
            Payload = data
        };
    }
}