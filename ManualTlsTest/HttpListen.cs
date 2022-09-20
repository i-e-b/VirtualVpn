using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using VirtualVpn.Helpers;

namespace ManualTlsTest;

public class HttpListen
{
    public static bool Running = true;
    
    public static void ListenTcp()
    {
        Running = true;
        Console.WriteLine("I will listen for TCP messages on port 44300 and list them...");
        
        var certPem = File.ReadAllText("Certs/test-fullchain.pem");
        var keyPem = File.ReadAllText("Certs/test-privkey.pem");
        var x509 = ReWrap(X509Certificate2.CreateFromPem(certPem, keyPem));
        Console.WriteLine($"Re-wrapped cert has private side? {x509.HasPrivateKey}");

        var localEp = new IPEndPoint(IPAddress.Any, 44300);
        var tcpListener = new TcpListener(localEp);

        var buffer = new byte[65536];
        tcpListener.Start();

        // IEB: Continue from here. Get this SSL unwrapping working (call with real browser)
        // Then take the un-wrap logic over to VirtualVpn.VpnServer.MakeProxyCall
        while (Running)
        {
            Console.WriteLine("Waiting for a connection");
            using var client = tcpListener.AcceptTcpClient();
            Console.WriteLine("Got a connection. Reading...");

            using var stream = client.GetStream();
            
            using var sslStream = new SslStream(stream);
        
            sslStream.AuthenticateAsServer(x509, false, SslProtocols.Tls11|SslProtocols.Tls12, false);

            var read = sslStream.Read(buffer, 0, buffer.Length);

            Console.WriteLine(Bit.SafeString(buffer.Take(read)));

            sslStream.Write(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nHello!"));
        }
    }

    /// <summary>
    /// Fix cert (due to bug https://github.com/dotnet/runtime/issues/23749 )
    /// Looks like this is a bug in Windows, and might not affect Linux
    /// </summary>
    /// <remarks>The bug was closed at time of writing, but not actually fixed.
    /// See also ( https://github.com/dotnet/runtime/issues/45680 and https://github.com/dotnet/runtime/issues/23749 and https://github.com/dotnet/runtime/issues/27826 )</remarks>
    private static X509Certificate2 ReWrap(X509Certificate2 createFromPem)
    {
        return new X509Certificate2(
            createFromPem.Export(
                X509ContentType.Pkcs12
            )/*, "", (X509KeyStorageFlags)36*/
        );
    }
}