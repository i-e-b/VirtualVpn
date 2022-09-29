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
        
        var localEp = new IPEndPoint(IPAddress.Any, 44300);
        var tcpListener = new TcpListener(localEp);

        var buffer = new byte[65536];
        tcpListener.Start();
        
        var authOptions = new SslServerAuthenticationOptions{
            AllowRenegotiation = true,
            ClientCertificateRequired = false,
            EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            ServerCertificateSelectionCallback = CertSelect,
            EnabledSslProtocols = SslProtocols.Tls11 | SslProtocols.Tls12 /*|SslProtocols.Tls13*/, // DO NOT use 1.3 on Windows: https://github.com/dotnet/runtime/issues/1720
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck
        };
        
        while (Running)
        {
            Console.WriteLine("Waiting for a connection");
            //using var client = tcpListener.AcceptTcpClient();
            using var socket = tcpListener.AcceptSocket();
            Console.WriteLine("Got a connection. Reading...");

            using var stream = new SocketStream(socket);
            Console.WriteLine("...got socket stream");
            
            //System.Security.Cryptography.RSAOpenSsl.Create().
            using var sslStream = new SslStream(stream);
            Console.WriteLine("...got SSL stream");
        
            //sslStream.AuthenticateAsServer(x509, true, SslProtocols.Tls11|SslProtocols.Tls12|SslProtocols.Tls13, false);
            sslStream.AuthenticateAsServer(authOptions);
            Console.WriteLine("...TLS authentication complete");

            var read = sslStream.Read(buffer, 0, buffer.Length);
            Console.WriteLine("...read request");

            Console.WriteLine(Bit.SafeString(buffer.Take(read)));

            Console.WriteLine("...writing response");
            sslStream.Write(Encoding.UTF8.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nHello!"));
            Console.WriteLine("...done!");
        }
    }

    private static X509Certificate CertSelect(object sender, string? hostname)
    {
        var cert = GetX509Certificate();
        Console.WriteLine($"Returning cert for {hostname??"<unknown>"} with {cert.Subject}");

        if (Platform.Current() == Platform.Kind.Windows)
        {
            // There are a bunch of bugs, and no-one seems to want to fix them.
            // See
            //  - https://github.com/dotnet/runtime/issues/23749
            //  - https://github.com/dotnet/runtime/issues/45680
            //  - https://github.com/dotnet/runtime/issues/23749
            //  - https://github.com/dotnet/runtime/issues/27826
            // These bugs were closed at time of writing, but not actually fixed.
            
            if (hostname is null || !cert.Subject.Contains(hostname))
                throw new Exception("Windows does not support providing certificates without matching 'CN'. " +
                                    "If you are testing, consider putting the DNS name in C:\\Windows\\System32\\drivers\\etc\\hosts file");
        }

        return cert;
    }

    private static X509Certificate GetX509Certificate()
    {
        var certPem = File.ReadAllText("Certs/test-fullchain.pem");
        var keyPem = File.ReadAllText("Certs/test-privkey.pem");
        var certFromPem = X509Certificate2.CreateFromPem(certPem, keyPem);

        if (Platform.Current() != Platform.Kind.Windows) return certFromPem;
        
        return ReWrap(certFromPem);
    }

    private static X509Certificate2 ReWrap(X509Certificate2 certFromPem)
    {
        return new X509Certificate2(certFromPem.Export(X509ContentType.Pkcs12));
    }
}