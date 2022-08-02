// See https://aka.ms/new-console-template for more information

using System.Net;
using System.Net.Sockets;
using RawSocketTest;

Console.WriteLine("Setup");


//EndPoint target = new IPEndPoint(new IPAddress(new byte[]{197,250,65,132}), 500); // M-P
IPEndPoint target = new IPEndPoint(new IPAddress(new byte[]{159,69,13,126}), 500);  // Gerty
using var server = new UdpServer();

Thread.Sleep(1000);

server.Start();

Console.WriteLine("trying to send raw");
var rnd = new Random();

var message = new IkeMessage
{
    SpiI = (ulong)rnd.NextInt64(),
    SpiR = 0,
    Version = IkeVersion.IkeV2,
    Exchange = ExchangeType.IKE_SA_INIT,
    MessageFlag = MessageFlag.Initiator,
    MessageId = 0,
    FirstPayload = PayloadType.SA,
    PayloadLength = 0
};


var buf = message.ToBytes();

for (int i = 0; i < 100; i++)
{
    var sent = server.SendTo(buf, SocketFlags.None, target);
    Console.WriteLine($"Sent {sent} bytes. Waiting for response ({i+1} of 100)");
    Thread.Sleep(500);
}
