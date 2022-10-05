using System.Diagnostics;
using System.Net;
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
public class TcpIpTrafficTests
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
        
        alice.StartConnect(IpV4Address.Any, 1147, IpV4Address.Localhost, 555);
        
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
        
        // check that a close gets propagated to the adaptor
        Assert.That(clientNet.IsClosed, Is.True, "client adaptor not closed");
        Assert.That(serverNet.IsClosed, Is.True, "server adaptor not closed");
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
        
        // check that a close gets propagated to the adaptor
        Assert.That(clientNet.IsClosed, Is.True, "client adaptor not closed");
        Assert.That(serverNet.IsClosed, Is.True, "server adaptor not closed");
    }

    [Test]
    public void tcp_socket_send_and_receive_data()
    {
        Log.SetLevel(LogLevel.Everything);
        
        //
        // Do a full transaction, with data coming from both sides
        //
        
        const string sendMessage = "This is a short message from the client to the server";
        const string replyMessage = "This is a different message from the server back to the client in response to the first";
        TwoConnectedSockets(out var server, out var serverNet, out var client, out var clientNet);

        // Send a message
        var senderBuffer = Encoding.UTF8.GetBytes(sendMessage);
        client.SendData(senderBuffer);
        
        // Transmit
        Log.Info($"Send ##### Data is {senderBuffer.Length} bytes. Client has {client.BytesOfSendDataWaiting} bytes, server has {server.BytesOfReadDataWaiting} bytes. #######");
        SendAllWaitingPackets(server, serverNet, client, clientNet);
        Log.Info($"Send ##### Data is {senderBuffer.Length} bytes. Client has {client.BytesOfSendDataWaiting} bytes, server has {server.BytesOfReadDataWaiting} bytes. #######");
        
        // Check message is received and ACKd client->server
        Assert.That(server.ReadDataState, Is.EqualTo(TcpReadDataState.FlushRequest), "Read complete flag on server");
        Assert.That(server.BytesOfReadDataWaiting, Is.EqualTo(senderBuffer.Length), "server did not receive all data");
        Assert.That(client.BytesOfSendDataWaiting, Is.Zero, "not all sent data was acknowledged by server");

        // Read the data that was received
        var readBuffer = new byte[server.BytesOfReadDataWaiting];
        var actual = server.ReadData(readBuffer);
        Assert.That(actual, Is.EqualTo(senderBuffer.Length), "Transmit size");
        Assert.That(Encoding.UTF8.GetString(readBuffer), Is.EqualTo(sendMessage), "Transmit message");
        
        // Send a reply
        var replyBuffer = Encoding.UTF8.GetBytes(replyMessage);
        server.SendData(replyBuffer);
       
        // Transmit 
        Log.Info($"Receive ##### Data is {replyBuffer.Length} bytes. Client has {client.BytesOfReadDataWaiting} bytes, server has {server.BytesOfSendDataWaiting} bytes. #######");
        SendAllWaitingPackets(server, serverNet, client, clientNet);
        Log.Info($"Receive ##### Data is {replyBuffer.Length} bytes. Client has {client.BytesOfReadDataWaiting} bytes, server has {server.BytesOfSendDataWaiting} bytes. #######");

        // Check message is received and ACKd server->client
        Assert.That(client.ReadDataState, Is.EqualTo(TcpReadDataState.FlushRequest), "Read complete flag on client");
        Assert.That(client.BytesOfReadDataWaiting, Is.EqualTo(replyBuffer.Length), "client did not receive all data");
        Assert.That(server.BytesOfSendDataWaiting, Is.Zero, "not all sent data was acknowledged by client");
        
        // Read the data that was received
        readBuffer = new byte[client.BytesOfReadDataWaiting];
        actual = client.ReadData(readBuffer);
        Assert.That(actual, Is.EqualTo(replyBuffer.Length), "Transmit size");
        Assert.That(Encoding.UTF8.GetString(readBuffer), Is.EqualTo(replyMessage), "Transmit message");
        
        
        // Now we should be able to close the connection
        client.StartClose();
        SendAllWaitingPacketsForClosing(server, serverNet, client, clientNet);
        
        Assert.That(client.State, Is.EqualTo(TcpSocketState.Closed), "client state");
        Assert.That(server.State, Is.EqualTo(TcpSocketState.Closed), "server state");
        
        // check that a close gets propagated to the adaptor
        Assert.That(clientNet.IsClosed, Is.True, "client adaptor not closed");
        Assert.That(serverNet.IsClosed, Is.True, "server adaptor not closed");
    }
    
    [Test]
    public void tcp_socket_send_and_receive_when_receiver_stalls()
    {
        Log.SetLevel(LogLevel.Debug);
        
        //
        // Do a full transaction, with data coming from both sides
        //
        var rnd= new Random();
        var bytesIn = new byte[70_000]; // needs to be larger than 65535, which is the maximum window
        rnd.NextBytes(bytesIn);
        
        TwoConnectedSockets(out var server, out var serverNet, out var client, out var clientNet);

        // Send a message
        var idx = 0;
        while (idx < bytesIn.Length)
        {
            var sizeToSend = Math.Min(idx+1000, bytesIn.Length);
            client.SendData(bytesIn, idx, sizeToSend);
            idx += sizeToSend;
        }

        // Transmit
        Log.Info($"Send ##### Data is {bytesIn.Length} bytes. Client has {client.BytesOfSendDataWaiting} bytes, server has {server.BytesOfReadDataWaiting} bytes. #######");
        SendAllWaitingPackets(server, serverNet, client, clientNet);
        Log.Info($"Send ##### Data is {bytesIn.Length} bytes. Client has {client.BytesOfSendDataWaiting} bytes, server has {server.BytesOfReadDataWaiting} bytes. #######");
        
        // This should stop at the receive window size, as we aren't pulling any data back out
        
        // Check message is received and ACKd client->server
        Assert.That(server.BytesOfReadDataWaiting, Is.EqualTo(65535), "server did not receive all data");
        Assert.That(client.BytesOfSendDataWaiting, Is.EqualTo(bytesIn.Length - 65535 - 512), "not all sent data was acknowledged by server");
        
        // Read all the data out (and ditch it)
        var receptionBuffer = new byte[65535];
        var read = server.ReadData(receptionBuffer);
        Assert.That(read, Is.EqualTo(65535), "window size");
        Assert.That(server.BytesOfReadDataWaiting, Is.Zero, "backlog cleared");
        
        // Trigger RTO on the client to get the nudge packet re-sent
        client.TriggerRtoTimer();
        client.EventPump();
        
        // NOW we should be able to continue transferring data
        Log.Info($"Send ##### Data is {bytesIn.Length} bytes. Client has {client.BytesOfSendDataWaiting} bytes, server has {server.BytesOfReadDataWaiting} bytes. #######");
        SendAllWaitingPackets(server, serverNet, client, clientNet);
        Log.Info($"Send ##### Data is {bytesIn.Length} bytes. Client has {client.BytesOfSendDataWaiting} bytes, server has {server.BytesOfReadDataWaiting} bytes. #######");
        
        Assert.That(server.BytesOfReadDataWaiting, Is.EqualTo(bytesIn.Length - 65535), "server did not receive all data");
        Assert.That(client.BytesOfSendDataWaiting, Is.Zero, "not all sent data was acknowledged by server");
    }

    [Test]
    public void timeout_trigger_fires_once_after_time_expires()
    {
        var triggered = 0;
        var subject = new TcpTimedEvent(_ => { triggered++; }, TimeSpan.FromMilliseconds(125));
        
        // doesn't fire before timeout
        subject.TriggerIfExpired();
        Assert.That(triggered, Is.Zero);
        
        Thread.Sleep(200);
        
        // will fire now
        subject.TriggerIfExpired();
        Assert.That(triggered, Is.EqualTo(1));
        
        // but not again
        subject.TriggerIfExpired();
        Assert.That(triggered, Is.EqualTo(1));
        
        // after resetting,
        subject.Reset();
        
        // doesn't fire before timeout
        subject.TriggerIfExpired();
        Assert.That(triggered, Is.EqualTo(1));
        
        Thread.Sleep(200);
        
        // will fire now
        subject.TriggerIfExpired();
        Assert.That(triggered, Is.EqualTo(2));
        
        // but not again
        subject.TriggerIfExpired();
        Assert.That(triggered, Is.EqualTo(2));
    }

    [Test]
    public void packets_are_resent_if_no_ack_in_timeout()
    {
        Log.SetLevel(LogLevel.Everything);
        
        const string sendMessage = "This is a short message from the client to the server";
        TwoConnectedSockets(out _, out _, out var client, out var clientNet);

        // Send a message
        var senderBuffer = Encoding.UTF8.GetBytes(sendMessage);
        client.SendData(senderBuffer);
        
        Assert.That(clientNet.SentSegments.Count, Is.EqualTo(0), "before first tick");
        client.EventPump();
        Assert.That(clientNet.SentSegments.Count, Is.EqualTo(1), "after first tick");
        client.EventPump();
        Assert.That(clientNet.SentSegments.Count, Is.EqualTo(1), "after second tick");
        
        // expire the retry-time-out
        client.TriggerRtoTimer();
        client.EventPump();
        Assert.That(clientNet.SentSegments.Count, Is.EqualTo(2), "after timeout");
    }

    /// <summary>
    /// Send packets in both directions until both are empty.
    /// This will check that error flag remains at 'success'
    /// </summary>
    private static void SendAllWaitingPackets(TcpSocket server, TestAdaptor serverNet, TcpSocket client, TestAdaptor clientNet)
    {
        var rounds = 0;
        while (rounds < 2)
        {
            var transmit = false;
            
            Log.Debug("------------- server -------------------");
            transmit |= TryRouteNextMessageAndRemove(from: clientNet, to: server);
            server.EventPump();
            Assert.That(server.ErrorCode, Is.EqualTo(SocketError.Success), $"server faulted: {server.State}");
            
            Log.Debug("------------- client -------------------");
            transmit |= TryRouteNextMessageAndRemove(from: serverNet, to: client);
            client.EventPump();
            Assert.That(client.ErrorCode, Is.EqualTo(SocketError.Success), "client faulted");
            
            if ( transmit ) rounds = 0;
            else rounds++;
        }
    }
    
    /// <summary>
    /// Send packets in both directions until both are empty.
    /// This will ignore any error flags, and will trigger timers
    /// </summary>
    private static void SendAllWaitingPacketsForClosing(TcpSocket server, TestAdaptor serverNet, TcpSocket client, TestAdaptor clientNet)
    {
        var rounds = 0;
        while (rounds < 2)
        {
            var transmit = false;
            
            Log.Debug("------------- server -------------------");
            transmit |= TryRouteNextMessageAndRemove(from: clientNet, to: server);
            server.TriggerMainWaitTimer();
            server.EventPump();
            
            Log.Debug("------------- client -------------------");
            transmit |= TryRouteNextMessageAndRemove(from: serverNet, to: client);
            server.TriggerMainWaitTimer();
            client.EventPump();
            
            if ( transmit ) rounds = 0;
            else rounds++;
        }
    }


    /// <summary>
    /// Make sure checksum is correct, then send from an adaptor to a socket
    /// </summary>
    private static bool TryRouteNextMessageAndRemove(TestAdaptor from, TcpSocket to)
    {
        if (from.SentSegments.Count < 1) return false;
        
        var tcp = from.SentSegments[0];
        var route = from.SentRoutes[0];
        
        from.SentSegments.RemoveAt(0);
        from.SentRoutes.RemoveAt(0);
        
        // update checksum
        Assert.True(tcp.ValidateChecksum(route.LocalAddress.Value, route.RemoteAddress.Value), "sender's checksum");
        
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
        
        return true;
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
        serverAdaptor = new TestAdaptor("server");
        server = new TcpSocket(serverAdaptor);
        server.Listen();
        
        clientAdaptor = new TestAdaptor("client");
        client = new TcpSocket(clientAdaptor);
        client.StartConnect(IpV4Address.Any, 1066, IpV4Address.Localhost, 46781);
        
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
}

public class TestAdaptor : ITcpAdaptor
{
    private readonly string _name;
    public bool IsClosed { get; set; }
    
    public List<TcpSegment> SentSegments { get; set; }
    public List<TcpRoute> SentRoutes { get; set; }

    public TestAdaptor(string name="TestAdaptor")
    {
        LastContact = new Stopwatch();
        LocalAddress = IpV4Address.Localhost.Value;
        SocketThroughTunnel = new TcpSocket(this);
        RemoteAddress = IpV4Address.Localhost.Value;
        Gateway = IpV4Address.Localhost.MakeEndpoint(0);
        LocalPort = 0;
        RemotePort = 0;
        
        _name = name;
        SentRoutes = new List<TcpRoute>();
        SentSegments = new List<TcpSegment>();
        IsClosed = false;
    }
    
    public void Close()
    {
        IsClosed = true;
    }

    public void Closing() { }

    public void Reply(TcpSegment seg, TcpRoute route)
    {
        Log.Info($"Adaptor {_name} - have packet to send: Flags={seg.Flags.ToString()}, Seq={seg.SequenceNumber}, Ack={seg.AcknowledgmentNumber}, target={route.RemoteAddress}:{route.RemotePort}");
        SentSegments.Add(seg);
        SentRoutes.Add(route);
    }

    public void Accept(IpV4Packet ipv4)
    {
        throw new NotImplementedException();
    }

    public bool EventPump()
    {
        throw new NotImplementedException();
    }

    public SenderPort SelfKey => new(new byte[] { 1, 2, 3, 4 }, 5);

    public Stopwatch LastContact { get; }
    public DateTime StartTime => DateTime.UtcNow;
    public byte[] LocalAddress { get; }
    public TcpSocket SocketThroughTunnel { get; }
    public int LocalPort { get; }
    public byte[] RemoteAddress { get; }
    public int RemotePort { get; }
    public IPEndPoint Gateway { get; }
    public bool TunnelConnectionIsClosedOrFaulted() => false;

    public bool WebAppConnectionIsFaulted() => false;
    public string Describe() => "test adaptor";

    public void Clear()
    {
        SentSegments.Clear();
        SentRoutes.Clear();
    }

    public bool IsEmpty() => SentSegments.Count < 1 && SentRoutes.Count < 1;

    public void Dispose()
    {
    }
}