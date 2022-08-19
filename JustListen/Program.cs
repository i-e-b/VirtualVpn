// See https://aka.ms/new-console-template for more information

using System.Net;
using System.Net.Sockets;
using System.Text;
using VirtualVpn.Enums;
using VirtualVpn.Helpers;
using VirtualVpn.InternetProtocol;
using VirtualVpn.TransmissionControlProtocol;

Console.Write("[T]CP, [U]DP, [S]end packets, [L]isten on socket 5223 ");
var x = Console.Read();

if (x == 'u' || x == 'U')
{
    ListenUdp();
} else if (x == 't' || x == 'T')
{
    ListenTcp();
} else if (x == 's' || x == 'S')
{
    SendPackets();
}else if (x == 'l' || x == 'L')
{
    ListenSocket5223();
}
else
{
    Console.WriteLine("\r\nWhat?");
}

void SendPackets()
{
    Console.WriteLine("I will try to send packet to port 5223 a few times");

    using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
    sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);

    for (int i = 0; i < 3; i++)
    {
        var tcp = new TcpSegment
        {
            SourcePort = 456,
            DestinationPort = 5223,
            SequenceNumber = 0,
            AcknowledgmentNumber = 0,
            DataOffset = 0,
            Reserved = 0,
            Flags = TcpSegmentFlags.SynAck,
            WindowSize = 0,
            Checksum = 0,
            UrgentPointer = 0,
            Options = Array.Empty<byte>(),
            Payload = Array.Empty<byte>()
        };
        var ip = new IpV4Packet
        {
            Version = IpV4Version.Version4,
            HeaderLength = 5,
            ServiceType = 0,
            TotalLength = 20,
            PacketId = 0,
            Flags = IpV4HeaderFlags.None,
            FragmentIndex = 0,
            Ttl = 0,
            Protocol = IpV4Protocol.TCP,
            Checksum = 0,
            Source = new IpV4Address { Value = new byte[] { 55, 55, 55, 40 } },
            Destination = IpV4Address.Localhost,
            Options = Array.Empty<byte>()
        };
        
        //new IpHelper ();
        
        tcp.UpdateChecksum(ip.Source.Value, ip.Destination.Value);
        var raw = ByteSerialiser.ToBytes(ip);
        
        ip.Payload = ByteSerialiser.ToBytes(tcp);
        ip.UpdateChecksum();

        //var written = sock.Send(raw);
        var written = sock.SendTo(raw, new IPEndPoint(IPAddress.Loopback, 5223));
        Console.WriteLine($"Wrote {written}");
    }
}

void ListenSocket5223()
{
    Console.WriteLine("I will listen for any messages on port 5223 and list them...");

    using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
    sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
    
    sock.Bind(new IPEndPoint(IPAddress.Any, 5223));

    var buffer = new byte[65536];
    
    while (true)
    {
        Console.WriteLine("Waiting for data");
        EndPoint endPoint = new IPEndPoint(IPAddress.Any, 5223);
        var bytes = sock.ReceiveFrom(buffer, ref endPoint);
        
        ByteSerialiser.FromBytes<IpV4Packet>(buffer.Take(bytes), out var pkt);
        Console.WriteLine(TypeDescriber.Describe(pkt));
        ByteSerialiser.FromBytes<TcpSegment>(pkt.Payload, out var tcp);
        Console.WriteLine(TypeDescriber.Describe(tcp));
        
        var ip = endPoint as IPEndPoint;
        Console.WriteLine($"Got data from {ip?.Address.ToString()}:{ip?.Port}. Will try to transfer to port 5223");
        Console.WriteLine(Bit.SafeString(tcp.Payload));
    }
}

void ListenUdp()
{
    Console.WriteLine("I will listen for UDP messages on port 5223 and list them...");

    var localEp = new IPEndPoint(IPAddress.Any, 5223);
    var tcpListener = new UdpClient(localEp);

    while (true)
    {
        Console.WriteLine("Waiting for a connection");
        var endPoint = new IPEndPoint(IPAddress.Any, 0);
        var bytes = tcpListener.Receive(ref endPoint);
        
        Console.WriteLine("Got UDP datagram");
        Console.WriteLine(Bit.SafeString(bytes));
    }
}

void ListenTcp()
{
    Console.WriteLine("I will listen for TCP messages on port 5223 and list them...");

    var localEp = new IPEndPoint(IPAddress.Any, 5223);
    var tcpListener = new TcpListener(localEp);

    var buffer = new byte[65536];
    tcpListener.Start();

    while (true)
    {
        Console.WriteLine("Waiting for a connection");
        using var client = tcpListener.AcceptTcpClient();
        Console.WriteLine("Got a connection. Reading...");

        using var stream = client.GetStream();

        var read = stream.Read(buffer, 0, buffer.Length);

        Console.WriteLine(Bit.SafeString(buffer.Take(read)));

        stream.Write(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nHello!"));
    }
}

