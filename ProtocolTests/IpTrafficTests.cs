using System.Net.Sockets;
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
    public void ReceiveBuffer_test()
    {
        Assert.That(ReceiveBuffer.Min(1, 2, 3), Is.EqualTo(1), "a1");
        Assert.That(ReceiveBuffer.Min(1, 3, 2), Is.EqualTo(1), "a2");
        Assert.That(ReceiveBuffer.Min(2, 1, 3), Is.EqualTo(1), "b1");
        Assert.That(ReceiveBuffer.Min(3, 1, 2), Is.EqualTo(1), "b2");
        Assert.That(ReceiveBuffer.Min(2, 3, 1), Is.EqualTo(1), "c1");
        Assert.That(ReceiveBuffer.Min(3, 2, 1), Is.EqualTo(1), "c2");
    }

    [Test]
    public void tcp_socket_connection()
    {
        Log.SetLevel(LogLevel.Everything);
        
        //
        // We test the two sockets against each other.
        // One will be the server (passive/listen)
        // and the other the client (active).
        // 
        // This test will step through each part of
        // The handshake until both are in Established
        // state.
        //
        
        var aliceAdaptor = new TestAdaptor();
        var alice = new TcpSocket(aliceAdaptor);
        
        var bobAdaptor = new TestAdaptor();
        var bob = new TcpSocket(bobAdaptor);
        
        // Alice (active) is going to connect to Bob (passive/listen)
        bob.Listen();
        
        Assert.That(bob.State, Is.EqualTo(TcpSocketState.Listen), "state");
        Assert.That(bob.ErrorCode, Is.EqualTo(SocketError.Success), "err");
        
        alice.StartConnect(IpV4Address.Localhost, 555);
        
        // Outgoing SYN
        Assert.That(aliceAdaptor.SentSegments.Count, Is.EqualTo(1), "sent segments");
        Assert.That(aliceAdaptor.SentRoutes.Count, Is.EqualTo(1), "sent routes");
        Assert.That(alice.State, Is.EqualTo(TcpSocketState.SynSent), "state");
        Assert.That(alice.ErrorCode, Is.EqualTo(SocketError.Success), "err");
        
        // deliver SYN to bob, expect SYN+ACK back
        CheckAndRouteLatestMessage(from: aliceAdaptor, to: bob, TcpSegmentFlags.Syn);
        
        Assert.That(bobAdaptor.SentSegments.Count, Is.EqualTo(1), "sent segments");
        Assert.That(bobAdaptor.SentRoutes.Count, Is.EqualTo(1), "sent routes");
        Assert.That(bob.State, Is.EqualTo(TcpSocketState.SynReceived), "state");
        Assert.That(bob.ErrorCode, Is.EqualTo(SocketError.Success), "err");
        
        // deliver SYN+ACK to alice, expect final ACK. Alice should be established
        CheckAndRouteLatestMessage(from: bobAdaptor, to: alice, TcpSegmentFlags.SynAck);
        
        Assert.That(aliceAdaptor.SentSegments.Count, Is.EqualTo(2), "sent segments");
        Assert.That(aliceAdaptor.SentRoutes.Count, Is.EqualTo(2), "sent routes");
        Assert.That(alice.State, Is.EqualTo(TcpSocketState.Established), "state");
        Assert.That(alice.ErrorCode, Is.EqualTo(SocketError.Success), "err");
        
        // deliver final ACK to bob, expect no further message. Bob should be established
        CheckAndRouteLatestMessage(from: aliceAdaptor, to: bob, TcpSegmentFlags.Ack);
        
        Assert.That(bobAdaptor.SentSegments.Count, Is.EqualTo(1), "sent segments");
        Assert.That(bobAdaptor.SentRoutes.Count, Is.EqualTo(1), "sent routes");
        Assert.That(bob.State, Is.EqualTo(TcpSocketState.Established), "state");
        Assert.That(bob.ErrorCode, Is.EqualTo(SocketError.Success), "err");
    }

    /// <summary>
    /// Make sure checksum is correct, then send from an adaptor to a socket
    /// </summary>
    private static void CheckAndRouteLatestMessage(TestAdaptor from, TcpSocket to, TcpSegmentFlags flags)
    {
        var tcp = from.SentSegments.Last();
        var route = from.SentRoutes.Last();
        
        // update checksum
        Assert.True(tcp.ValidateChecksum(route.LocalAddress.Value, route.RemoteAddress.Value), "sender's checksum");
        
        Assert.That(tcp.Flags, Is.EqualTo(flags), "flags");
        
        // make an IPv4 wrapper
        var tcpBytes = ByteSerialiser.ToBytes(tcp);

        var ip = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20 + tcpBytes.Length,
            PacketId = 0,
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 0,
            Protocol = IpV4Protocol.TCP,
            Checksum = 0,
            Source = route.LocalAddress,
            Destination = route.RemoteAddress,
            Options = Array.Empty<byte>(),
            Payload = tcpBytes
        };
        ip.UpdateChecksum();
        
        to.FeedIncomingPacket(tcp, ip);
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