using VirtualVpn;
using VirtualVpn.Helpers;
using VirtualVpn.Web;

Console.WriteLine($"Starting up VirtualVPN. Current platform={Platform.Current().ToString()}");

Log.SetLevel(Settings.DefaultLogLevel);

if (Settings.RunAirliftSite)
{
    // Mini web site for file captures
    var http = new HttpCapture();
    http.Start();
}

// Run the VPN server
// This also listens for console input
// for various commands, including for
// starting IP-SEC connections, and to
// set log levels.
using var vpnServer = new VpnServer();
vpnServer.Run();
