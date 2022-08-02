// See https://aka.ms/new-console-template for more information

using System.Net;
using System.Net.Sockets;
using System.Text;
using RawSocketTest;

const int megabyte = 1048576;
var resultBuf = new byte[1 * megabyte];

Console.WriteLine("Setup");

using var sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp) { Blocking = true };

EndPoint target = new IPEndPoint(new IPAddress(new byte[]{197,250,65,132}), 500);
//sock.Bind(new IPEndPoint(0, 500));
//sock.Connect("197.250.65.132", 500);

Console.WriteLine("trying to send raw");
var buf = Encoding.UTF8.GetBytes("hello");
sock.SendTo(buf, SocketFlags.None, target);

Console.WriteLine("trying to receive raw");
var actual = sock.ReceiveFrom(resultBuf,0,resultBuf.Length, SocketFlags.None, ref target);

Console.WriteLine($"Got {actual} bytes");
 
 
 /*
IConnectableStreamSource source = new SocketStreamFactory();

var stream = source.ConnectUnsecured(new Uri("udp://197.250.65.132:500", UriKind.Absolute), TimeSpan.FromSeconds(5));

Console.WriteLine("Sending data...");
var buf = Encoding.UTF8.GetBytes("hello");
stream.Write(buf, 0, buf.Length);

Thread.Sleep(250);

Console.WriteLine("Reading data...");
var resultBuf = new byte[1 * megabyte];
var actual = stream.Read(resultBuf, 0, resultBuf.Length);

Console.WriteLine($"Read {actual} bytes.");
Console.WriteLine(Encoding.UTF8.GetString(resultBuf, 0, actual));*/