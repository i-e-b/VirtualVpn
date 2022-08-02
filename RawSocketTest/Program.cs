// See https://aka.ms/new-console-template for more information

using System.Net;
using RawSocketTest;
using SkinnyJson;

Console.WriteLine("Setup");
Json.DefaultParameters.EnableAnonymousTypes = true;

// Use Gerty for testing. Run "JustListen" to check your connection is working.
// You may need to do lots of firewall poking and NAT rules.
// Switch on ipsec on Gerty (`ipsec restart`), make sure there is a ruleset for the test PC.

//var target = new IPEndPoint(new IPAddress(new byte[]{197,250,65,132}), 500); // M-P
var target = new IPEndPoint(new IPAddress(new byte[]{159,69,13,126}), 500);  // Gerty
using var server = new UdpServer(IkeResponder, null);

Thread.Sleep(1000);

server.Start();

Console.WriteLine("trying to send raw");
var rnd = new Random();
var mySpi = (ulong)rnd.NextInt64();

var message = new IkeMessage
{
    SpiI = mySpi,
    SpiR = 0,
    Version = IkeVersion.IkeV2,
    Exchange = ExchangeType.IKE_SA_INIT,
    MessageFlag = MessageFlag.Initiator,
    MessageId = 0,
    FirstPayload = PayloadType.NONE
};

message.AddPayload(PayloadType.SA, new byte[1]);

var buf = message.ToBytes();

var limit = 5;
for (int i = 0; i < limit; i++)
{
    //var sent = server.SendTo(buf, SocketFlags.None, target);
    server.SendIke(buf, target, out var sent);
    Console.WriteLine($"Sent {sent} bytes. Waiting for response ({i+1} of {limit})");
    Thread.Sleep(500);
}

void IkeResponder(byte[] rawData)
{
    var ikeMessage = IkeMessage.FromBytes(rawData);
    
    var str = Json.Freeze(ikeMessage);
    
    Console.WriteLine(str);
}