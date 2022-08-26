using NUnit.Framework;
using VirtualVpn.TcpProtocol;

// ReSharper disable InconsistentNaming

namespace ProtocolTests;

[TestFixture]
public class ReadWriteBufferTests
{
    [Test]
    public void can_write_and_read_from_the_read_buffer_in_chunks()
    {
        var subject = new ReceiveBuffer();

        // Simple ordered chunks
        subject.Insert(Seg(420, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }));
        subject.Insert(Seg(430, new byte[] { 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 }));
        subject.Insert(Seg(440, new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 }));
        Assert.That(subject.RemainingData(), Is.EqualTo(30), "remains");

        // Read back in same size chunks
        var buffer = new byte[10];

        var actual = subject.ReadOutAndUpdate(buffer, 0, 10);
        Assert.That(actual, Is.EqualTo(10), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(20), "remains");


        actual = subject.ReadOutAndUpdate(buffer, 0, 10);
        Assert.That(actual, Is.EqualTo(10), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(10), "remains");


        actual = subject.ReadOutAndUpdate(buffer, 0, 10);
        Assert.That(actual, Is.EqualTo(10), "length");
        Assert.That(buffer, Is.EqualTo(new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(0), "remains");


        // Should now be empty. Try final read to get zero
        actual = subject.ReadOutAndUpdate(buffer, 0, 10);
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
        Assert.That(buffer, Is.EqualTo(new byte[] { 29, 30, 0, 0, 0, 0, 0 }).AsCollection, "items");
        Assert.That(subject.RemainingData(), Is.EqualTo(0), "remains");


        // Should now be empty. Try final read to get zero
        actual = subject.ReadOutAndUpdate(buffer, 0, 10);
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
        Assert.That(buffer, Is.EqualTo(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }).AsCollection, "items");
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
        actual = subject.ReadOutAndUpdate(buffer, 0, 10);
        Assert.That(actual, Is.Zero, "length");
    }

    [Test]
    public void send_buffer_write_and_read()
    {
        var subject = new SendBuffer();
        var chunk_1 = new byte[] {  1,  2,  3,  4,  5,  6,  7,  8,  9, 10 };
        var chunk_2 = new byte[] { 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
        var chunk_3 = new byte[] { 21, 22, 23, 24, 25, 26, 27, 28, 29, 30 };

        // fill the buffer
        subject.SetStartSequence(420);
        subject.Write(chunk_1, 0, chunk_1.Length);
        subject.Write(chunk_2, 0, chunk_2.Length);
        subject.Write(chunk_3, 0, chunk_3.Length);

        Assert.That(subject.RemainingData(), Is.EqualTo(30), "data left");

        // read back a section without removing
        var read_1 = subject.Pull(420, 10);
        Assert.That(read_1, Is.EqualTo(chunk_1).AsCollection, "data");
        Assert.That(subject.Count(), Is.EqualTo(30), "buffered data");         // data is still in buffer,
        Assert.That(subject.RemainingData(), Is.EqualTo(20), "data not read"); //  but we note that it's been pulled
        
        // read back a section off alignment
        var read_2 = subject.Pull(425, 10);
        Assert.That(read_2, Is.EqualTo(new byte[] { 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }).AsCollection, "data");
        Assert.That(subject.Count(), Is.EqualTo(30), "buffered data");         // data is still in buffer,
        Assert.That(subject.RemainingData(), Is.EqualTo(15), "data not read"); //  but we note that it's been pulled

        // advance data
        subject.ConsumeTo(430);
        Assert.That(subject.Count(), Is.EqualTo(20), "buffered data");
        Assert.That(subject.RemainingData(), Is.EqualTo(15), "data left");
    }


    private void Clear(byte[] buffer)
    {
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] = 0;
        }
    }

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