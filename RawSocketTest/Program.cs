// See https://aka.ms/new-console-template for more information

using RawSocketTest;
using RawSocketTest.Helpers;

Log.SetLevel(Settings.DefaultLogLevel);

// Notify of anything coming across the wrong protocol
var echo1 = new TcpEcho(500);
var echo2 = new TcpEcho(4500);

// Run the VPN server
using var vpnServer = new VpnServer();
vpnServer.Run();
