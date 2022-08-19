// See https://aka.ms/new-console-template for more information

using System.Net;
using System.Net.Sockets;
using System.Text;
using VirtualVpn.Helpers;

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

