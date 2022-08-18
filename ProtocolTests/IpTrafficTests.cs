using System.Text;
using NUnit.Framework;
using VirtualVpn.TransmissionControlProtocol;

namespace ProtocolTests;

[TestFixture]
public class IpTrafficTests
{
    [Test]
    public void tcp_payload_checksum()
    {
        /*
        var data = Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n" +
            "Content-Length: 45\r\n" +
            "\r\n" +
            "Hello, world. How's it going? I'm VirtualVPN!"
        );
        var replyPkt = new TcpSegment
        {
            SourcePort = tcp.DestinationPort,
            DestinationPort = tcp.SourcePort,
            SequenceNumber = _localSeq,
            AcknowledgmentNumber = _remoteSeq,
            DataOffset = 5,
            Reserved = 0,
            Flags = TcpSegmentFlags.Ack | TcpSegmentFlags.Psh,
            WindowSize = tcp.WindowSize,
            Options = Array.Empty<byte>(),
            Payload = data
        };
        */
    }
}