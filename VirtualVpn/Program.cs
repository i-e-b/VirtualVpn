using VirtualVpn.Helpers;
using VirtualVpn.Logging;
using VirtualVpn.Web;

namespace VirtualVpn;

internal static class Program
{
    public static VpnServer? VpnServer;
    public static HttpListenerAndApi? HttpServer;

    /// <summary>
    /// Close and restart the http server.
    /// This should be done if the listen
    /// prefix changes.
    /// </summary>
    public static void RestartHttpServer()
    {
        HttpServer?.Stop();
        
        HttpServer = new HttpListenerAndApi();
        HttpServer.Start();
    }

    public static void Main(string[]? args)
    {
        Console.WriteLine($"Starting up VirtualVPN. Current platform={Platform.Current().ToString()}");
        if (args is null || args.Length < 1)
        {
            Console.WriteLine("Running in interactive mode. Press enter to see command list.");
        }

        Console.WriteLine("Starting logger");
        Log.SetLevel(Settings.DefaultLogLevel);
        Log.StartLokiServer();

        // Mini web site that provides an API,
        // and allows file captures to be retrieved if Settings.RunAirliftSite is on.
        Console.WriteLine("Starting HTTP host");
        HttpServer = new HttpListenerAndApi();
        HttpServer.Start();

        // Run the VPN server
        // This also listens for console input
        // for various commands, including for
        // starting IP-SEC connections, and to
        // set log levels.
        Console.WriteLine("Starting VPN host");
        using var vpnServer = new VpnServer();
        VpnServer = vpnServer;
        vpnServer.Run(args); // this will block the main thread until ended with 'quit' command
        
        Log.Warn("VirtualVPN is shutting down");
        VpnServer = null;
        HttpServer.Stop();
        Log.Stop();
    }
}