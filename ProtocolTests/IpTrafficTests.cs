using System.Net.Sockets;
using System.Text;
using NUnit.Framework;
using VirtualVpn;
using VirtualVpn.Enums;
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

    [Test] // See https://upload.wikimedia.org/wikipedia/commons/f/f6/Tcp_state_diagram_fixed_new.svg
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
        CheckAndRouteMostRecentMessage(from: aliceAdaptor, to: bob, TcpSegmentFlags.Syn);
        
        Assert.That(bobAdaptor.SentSegments.Count, Is.EqualTo(1), "sent segments");
        Assert.That(bobAdaptor.SentRoutes.Count, Is.EqualTo(1), "sent routes");
        Assert.That(bob.State, Is.EqualTo(TcpSocketState.SynReceived), "state");
        Assert.That(bob.ErrorCode, Is.EqualTo(SocketError.Success), "err");
        
        // deliver SYN+ACK to alice, expect final ACK. Alice should be established
        CheckAndRouteMostRecentMessage(from: bobAdaptor, to: alice, TcpSegmentFlags.SynAck);
        
        Assert.That(aliceAdaptor.SentSegments.Count, Is.EqualTo(2), "sent segments");
        Assert.That(aliceAdaptor.SentRoutes.Count, Is.EqualTo(2), "sent routes");
        Assert.That(alice.State, Is.EqualTo(TcpSocketState.Established), "state");
        Assert.That(alice.ErrorCode, Is.EqualTo(SocketError.Success), "err");
        
        // deliver final ACK to bob, expect no further message. Bob should be established
        CheckAndRouteMostRecentMessage(from: aliceAdaptor, to: bob, TcpSegmentFlags.Ack);
        
        Assert.That(bobAdaptor.SentSegments.Count, Is.EqualTo(1), "sent segments");
        Assert.That(bobAdaptor.SentRoutes.Count, Is.EqualTo(1), "sent routes");
        Assert.That(bob.State, Is.EqualTo(TcpSocketState.Established), "state");
        Assert.That(bob.ErrorCode, Is.EqualTo(SocketError.Success), "err");
    }

    [Test] // See https://upload.wikimedia.org/wikipedia/commons/5/55/TCP_CLOSE.svg
    public void tcp_socket_shutdown_from_established_client()
    {
        Log.SetLevel(LogLevel.Everything);
        
        //
        // Immediately shut-down a connection after it has started
        //
        TwoConnectedSockets(out var server, out var serverNet, out var client, out var clientNet);
        
        client.StartClose(); // this should advance the ack by one one the Fin segment?
        
        Assert.That(client.State, Is.EqualTo(TcpSocketState.FinWait1), "client state");
        Assert.That(server.State, Is.EqualTo(TcpSocketState.Established), "server state");
        
        RouteNextMessageAndRemove(from: clientNet, to: server, TcpSegmentFlags.Fin);
        Assert.That(clientNet.IsEmpty, "more client messages");
        Assert.That(server.State, Is.EqualTo(TcpSocketState.CloseWait), "server state");
        
        RouteNextMessageAndRemove(from: serverNet, to: client, TcpSegmentFlags.Ack);
        Assert.That(serverNet.IsEmpty, "more server messages");
        Assert.That(client.State, Is.EqualTo(TcpSocketState.FinWait2), "client state");
        
        // time passes
        server.TriggerMainWaitTimer(); server.EventPump();
        Assert.That(server.State, Is.EqualTo(TcpSocketState.LastAck), "server state"); // I think this should actually be LastAck
        
        
        RouteNextMessageAndRemove(from: serverNet, to: client, TcpSegmentFlags.Fin);
        Assert.That(serverNet.IsEmpty, "more server messages");
        Assert.That(client.State, Is.EqualTo(TcpSocketState.TimeWait), "client state");
        
        // more time passes
        client.TriggerMainWaitTimer(); client.EventPump();
        Assert.That(client.State, Is.EqualTo(TcpSocketState.Closed), "client state");
        
        RouteNextMessageAndRemove(from: clientNet, to: server, TcpSegmentFlags.Ack);
        Assert.That(clientNet.IsEmpty, "more client messages");
        Assert.That(server.State, Is.EqualTo(TcpSocketState.Closed), "server state");
    }
    
    [Test] // See https://upload.wikimedia.org/wikipedia/commons/f/f6/Tcp_state_diagram_fixed_new.svg
    public void tcp_socket_shutdown_from_established_server()
    {
        Log.SetLevel(LogLevel.Everything);
        
        //
        // Immediately shut-down a connection after it has started
        // Closing like this from the server side is less common?
        //
        
        TwoConnectedSockets(out var server, out var serverNet, out var client, out var clientNet);
        
        server.StartClose(); // 'Passive close' which starts with FIN+ACK 
        
        RouteNextMessageAndRemove(from: serverNet, to: client, TcpSegmentFlags.Fin | TcpSegmentFlags.Ack);
        Assert.That(serverNet.IsEmpty, "more server messages");
        Assert.That(server.State, Is.EqualTo(TcpSocketState.FinWait1), "server state");
        Assert.That(client.State, Is.EqualTo(TcpSocketState.CloseWait), "client state"); // ???
        
        RouteNextMessageAndRemove(from: clientNet, to: server, TcpSegmentFlags.Ack);
        Assert.That(clientNet.IsEmpty, "more client messages");
        Assert.That(client.State, Is.EqualTo(TcpSocketState.CloseWait), "client state");
        
        // time passes
        server.TriggerMainWaitTimer(); server.EventPump();
        client.TriggerMainWaitTimer(); client.EventPump();
        
        // both sides should consider themselves closed
        Assert.That(server.State, Is.EqualTo(TcpSocketState.Closed), "server state");
        Assert.That(client.State, Is.EqualTo(TcpSocketState.LastAck), "client state");
        
        client.TriggerMainWaitTimer(); client.EventPump();
        Assert.That(client.State, Is.EqualTo(TcpSocketState.Closed), "client state");
    }
    
    /// <summary>
    /// Make sure checksum is correct, then send from an adaptor to a socket
    /// </summary>
    private static void RouteNextMessageAndRemove(TestAdaptor from, TcpSocket to, TcpSegmentFlags flags)
    {
        Assert.That(from.SentSegments.Count, Is.GreaterThan(0), "No messages to route");
        
        var tcp = from.SentSegments[0];
        var route = from.SentRoutes[0];
        
        from.SentSegments.RemoveAt(0);
        from.SentRoutes.RemoveAt(0);
        
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

    /// <summary>
    /// Make sure checksum is correct, then send from an adaptor to a socket
    /// </summary>
    private static void CheckAndRouteMostRecentMessage(TestAdaptor from, TcpSocket to, TcpSegmentFlags flags)
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

    /// <summary>
    /// Create two sockets, and get the to the connected state.
    /// Assumes that this is working (tested by <see cref="tcp_socket_connection"/>)
    /// The adaptors traffic is cleared before being returned.
    /// </summary>
    private static void TwoConnectedSockets(
        out TcpSocket server, out TestAdaptor serverAdaptor,
        out TcpSocket client, out TestAdaptor clientAdaptor
        )
    {
        serverAdaptor = new TestAdaptor();
        server = new TcpSocket(serverAdaptor);
        server.Listen();
        
        clientAdaptor = new TestAdaptor();
        client = new TcpSocket(clientAdaptor);
        client.StartConnect(IpV4Address.Localhost, 46781);
        
        // SYN, expect SYN+ACK back
        CheckAndRouteMostRecentMessage(from: clientAdaptor, to: server, TcpSegmentFlags.Syn);
        // SYN+ACK, expect final ACK. Client should be established
        CheckAndRouteMostRecentMessage(from: serverAdaptor, to: client, TcpSegmentFlags.SynAck);
        // ACK, expect no further message. Server should be established
        CheckAndRouteMostRecentMessage(from: clientAdaptor, to: server, TcpSegmentFlags.Ack);
        
        serverAdaptor.Clear();
        clientAdaptor.Clear();
        
        Assert.That(client.State, Is.EqualTo(TcpSocketState.Established), "client state");
        Assert.That(server.State, Is.EqualTo(TcpSocketState.Established), "server state");
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

    public void Clear()
    {
        SentSegments.Clear();
        SentRoutes.Clear();
    }

    public bool IsEmpty() => SentSegments.Count < 1 && SentRoutes.Count < 1;
}