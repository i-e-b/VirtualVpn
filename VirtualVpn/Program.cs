// See https://aka.ms/new-console-template for more information

using VirtualVpn;
using VirtualVpn.Web;

Log.SetLevel(Settings.DefaultLogLevel);

// Mini web site to grab captures
var http = new HttpCapture();
http.Start();


// Run the VPN server
using var vpnServer = new VpnServer();
vpnServer.Run();
