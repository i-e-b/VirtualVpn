using System.Text;
using NUnit.Framework;
using VirtualVpn.EspProtocol;
using VirtualVpn.TcpProtocol;

namespace ProtocolTests;

[TestFixture]
public class IpTrafficTests
{
    [Test]
    public void tcp_payload_checksum()
    {
        var sourceAddress = new byte[] { 192, 168, 0, 40 };
        var destAddress = new byte[] { 55, 55, 55, 55 };

        var data = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Length: 45\r\n" +
            "\r\n" +
            "Hello, world. How's it going? I'm VirtualVPN!"
        );
        var replyPkt = new TcpSegment
        {
            SourcePort = 80,
            DestinationPort = 35036,
            SequenceNumber = 54778,
            AcknowledgmentNumber = 451536664,
            DataOffset = 5,
            Reserved = 0,
            Flags = TcpSegmentFlags.Ack | TcpSegmentFlags.Psh,
            WindowSize = 64813,
            Options = Array.Empty<byte>(),
            Payload = data
        };
        
        replyPkt.UpdateChecksum(sourceAddress, destAddress);
        
        // This checksum is kinda shitty, so the order of data doesn't
        // make much difference.
        
        Assert.That(replyPkt.Checksum, Is.EqualTo(0x3f38), $"Tcp checksum 0x{replyPkt.Checksum:x4} (should be 0x3f38)");
        
    }
    
    [Test]
    public void tcp_socket_lifecycle()
    {
        // TODO: test these against themselves.
        var aliceTunnel = new TestTunnel();
        var aliceAdaptor = new TestAdaptor();
        var alice = new TcpSocket(aliceAdaptor);
        
        var bobTunnel = new TestTunnel();
        var bobAdaptor = new TestAdaptor();
        var bob = new TcpSocket(bobAdaptor);
        
        //alice.ReceiveWithIpv4(segment, wrapper);
        // Required
        // -[x] receive packet
        // -[ ] connect to other side
        // -[ ] write data
        // -[ ] read data
        
        // Then should be able to plumb adaptor into receive
        
        Assert.Inconclusive("not implemented");
    }
}

public class TestAdaptor : ITcpAdaptor
{
    public void Close()
    {
        throw new NotImplementedException();
    }
}

public class TestTunnel : ITransportTunnel
{
}