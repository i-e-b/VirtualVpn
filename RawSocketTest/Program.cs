// See https://aka.ms/new-console-template for more information

using RawSocketTest;
using RawSocketTest.Web;

Log.SetLevel(Settings.DefaultLogLevel);

// Mini web site to grab captures
var http = new HttpCapture();
http.Start();


// Run the VPN server
using var vpnServer = new VpnServer();
vpnServer.Run();
