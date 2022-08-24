using System.Text;
using NUnit.Framework;
using VirtualVpn;
using VirtualVpn.Enums;
using VirtualVpn.EspProtocol;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;
using VirtualVpn.TcpProtocol;
// ReSharper disable InconsistentNaming

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
        Log.SetLevel(LogLevel.Everything);
        
        // TODO: test these against themselves.
        var aliceAdaptor = new TestAdaptor();
        var alice = new TcpSocket(aliceAdaptor);
        
        var bobAdaptor = new TestAdaptor();
        var bob = new TcpSocket(bobAdaptor);
       
        //alice.ReceiveWithIpv4(segment, wrapper);
        // Required
        // -[x] receive packet
        // -[ ] connect to other side
        // -[ ] write data
        // -[ ] read data
        
        //bob.Connect()
        
        MakeTcpPacket(555, 0, TcpSegmentFlags.Syn,out var seg1_alice, out var wrap1_alice);
        alice.Listen();
        alice.ReceiveWithIpv4(seg1_alice, wrap1_alice);
        
        Assert.That(aliceAdaptor.SentSegments.Count, Is.GreaterThan(0), "sent segments");
        Assert.That(aliceAdaptor.SentRoutes.Count, Is.GreaterThan(0), "sent routes");
        
        Assert.Inconclusive("not implemented");
    }

    private static void MakeTcpPacket(int seq, int ack, TcpSegmentFlags flags, out TcpSegment tcp, out IpV4Packet ip)
    {
        tcp = new TcpSegment
        {
            SourcePort = 123,
            DestinationPort = 456,
            SequenceNumber = seq,
            AcknowledgmentNumber = ack,
            DataOffset = 5,
            Reserved = 0,
            Flags = flags,
            WindowSize = 8122,
            Checksum = 0,
            UrgentPointer = 0,
            Options = Array.Empty<byte>(),
            Payload = Array.Empty<byte>()
        };
        
        tcp.UpdateChecksum(IpV4Address.Localhost.Value, IpV4Address.Localhost.Value);
        var tcpBytes = ByteSerialiser.ToBytes(tcp);

        ip = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + tcpBytes.Length,
            PacketId = 0,
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 0,
            Protocol = IpV4Protocol.HOPOPT,
            Checksum = 0,
            Source = IpV4Address.Localhost,
            Destination = IpV4Address.Localhost,
            Options = Array.Empty<byte>(),
            Payload = tcpBytes
        };
        
        ip.UpdateChecksum();
    }
}

public class TestAdaptor : ITcpAdaptor
{
    public bool IsClosed { get; set; }
    
    public List<TcpSegment> SentSegments { get; set; }
    public List<TcpRoute> SentRoutes { get; set; }

    public TestAdaptor()
    {
        SentRoutes = new List<TcpRoute>();
        SentSegments = new List<TcpSegment>();
        IsClosed = false;
    }
    
    public void Close()
    {
        IsClosed = true;
    }

    public void Reply(TcpSegment seg, TcpRoute route)
    {
        Log.Info($"TestAdaptor - got reply: Flags={seg.Flags.ToString()}, Seq={seg.SequenceNumber}, Ack={seg.AcknowledgmentNumber}, target={route.RemoteAddress}:{route.RemotePort}");
        SentSegments.Add(seg);
        SentRoutes.Add(route);
    }
}