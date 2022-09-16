using VirtualVpn.Helpers;
using VirtualVpn.Web;

namespace VirtualVpn;

internal static class Program
{
    public static VpnServer? VpnServer;

    public static void Main(string[] args)
    {
        Console.WriteLine($"Starting up VirtualVPN. Current platform={Platform.Current().ToString()}");

        Log.SetLevel(Settings.DefaultLogLevel);

// Mini web site that provides an API,
// and allows file captures to be retrieved if Settings.RunAirliftSite is on.
        var http = new HttpCapture();
        http.Start();

// Run the VPN server
// This also listens for console input
// for various commands, including for
// starting IP-SEC connections, and to
// set log levels.
        using var vpnServer = new VpnServer();
        VpnServer = vpnServer;
        vpnServer.Run();
        VpnServer = null;
    }
}