// See https://aka.ms/new-console-template for more information

using RawSocketTest;

Log.SetLevel(LogLevel.Info);

using var rt = new VpnServer();
rt.Run();
