using System.Net;
using System.Text;
using Tag;

namespace VirtualVpn.Web;

public class HttpCapture
{
    private readonly HttpListener _listener;
    private readonly Thread _listenThread;
    private readonly Thread _switchThread;

    public HttpCapture()
    {
        _listener = new HttpListener();
        _listener.IgnoreWriteExceptions = true;

        _listener.Prefixes.Add("http" + Settings.HttpPrefix);
        
        _listenThread = new Thread(ListenThreadLoop){IsBackground = true}; // handles actual web requests
        _switchThread = new Thread(SwitchThreadLoop){IsBackground = true}; // handles turning the listener on and off
    }
    
    public void Start()
    {
        _listenThread.Start();
        _switchThread.Start();
    }

    private void SwitchThreadLoop()
    {
        while (_switchThread.ThreadState != ThreadState.Stopped)
        {
            try
            {
                while (!Settings.RunAirliftSite)
                {
                    Thread.Sleep(1000);
                }

                Log.Info("Starting 'airlift' web handler");
                _listener.Start();

                while (Settings.RunAirliftSite)
                {
                    Thread.Sleep(1000);
                }

                Log.Info("Stopping 'airlift' web handler");
                _listener.Stop();
            }
            catch (Exception ex)
            {
                Log.Error("Fault while switching 'airlift' site", ex);
                Thread.Sleep(1000);
            }
        }
    }

    private void ListenThreadLoop()
    {
        while (_listenThread.ThreadState != ThreadState.Stopped)
        {
            while (!Settings.RunAirliftSite || !_listener.IsListening)
            {
                // Long sleep if we never switch on
                Thread.Sleep(5000);
            }
            
            Log.Info("Listening on port 8011");
            
            try
            {
                var ctx = _listener.GetContext();

                var url = ctx.Request.RawUrl ?? "<null>";
                Log.Debug($"HTTP listener responding to {url}");

                byte[] bytes;

                if (url == "/")
                {
                    ctx.Response.AddHeader("Content-Type", "text/html");
                    ctx.Response.StatusCode = 200;
                    bytes = ShowIndexPage();
                }
                else
                {
                    var path = Settings.FileBase + "/" + Path.GetFileName(url);
                    if (File.Exists(path))
                    {
                        ctx.Response.AddHeader("Content-Type", "text/plain");
                        ctx.Response.StatusCode = 200;
                        bytes = File.ReadAllBytes(path);
                    }
                    else
                    {
                        ctx.Response.AddHeader("Content-Type", "text/html");
                        ctx.Response.StatusCode = 404;
                        bytes = ShowErrorPage();
                    }
                }

                ctx.Response.OutputStream.Write(bytes);

                ctx.Response.Close();
            }
            catch (Exception ex)
            {
                Log.Error("Failure in 'airlift' handler", ex);
                Thread.Sleep(1000);
            }
        }
    }
    
    private static byte[] ShowErrorPage()
    {
        var head = T.g("head")[
            T.g("title")["VirtualVPN - airlift"]
        ];

        var body = T.g("body")[
            T.g("h1")["Virtual VPN"],
            T.g("p")["No such file"],
            T.g("a", "href", "/")["Home"]
        ];

        var document = T.g("html")[
            head,
            body
        ];

        return document.ToBytes(Encoding.UTF8);
    }

    private static byte[] ShowIndexPage()
    {
        var head = T.g("head")[
            T.g("title")["VirtualVPN - airlift"]
        ];

        var fileList = T.g("ul");
        var body = T.g("body")[
            T.g("h1")["Virtual VPN"],
            T.g("p")["Files ready for airlift:"],
            fileList
        ];

        var textFiles = Directory.EnumerateFiles(Settings.FileBase, "*.txt", SearchOption.TopDirectoryOnly);
        foreach (var path in textFiles)
        {
            var clean = Path.GetFileName(path);
            fileList.Add(T.g("li")[
                T.g("a", "href", clean)[clean]
            ]);
        }

        var document = T.g("html")[
            head,
            body
        ];
        
        return document.ToBytes(Encoding.UTF8);
    }
}