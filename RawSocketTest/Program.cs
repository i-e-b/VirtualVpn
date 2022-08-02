// See https://aka.ms/new-console-template for more information

using System.Text;
using RawSocketTest;

const int megabyte = 1048576;

Console.WriteLine("Hello, World!");

IConnectableStreamSource source = new SocketStreamFactory();

var stream = source.ConnectSSL(new Uri("udp://197.250.65.132:500", UriKind.Absolute), TimeSpan.FromSeconds(5));

var buf = Encoding.UTF8.GetBytes("hello");
stream.Write(buf, 0, buf.Length);

Thread.Sleep(250);

var resultBuf = new byte[1 * megabyte];
var actual = stream.Read(resultBuf, 0, resultBuf.Length);

Console.WriteLine($"Read {actual} bytes.");
Console.WriteLine(Encoding.UTF8.GetString(resultBuf, 0, actual));