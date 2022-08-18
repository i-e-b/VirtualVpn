using System.Net;
using System.Text;
using Tag;

namespace VirtualVpn.Web;

public class HttpCapture
{
    private readonly HttpListener _listener;
    private readonly Thread _thread;

    public HttpCapture()
    {
        _listener = new HttpListener();
        _listener.IgnoreWriteExceptions = true;

        _listener.Prefixes.Add("http" + Settings.HttpPrefix);
        
        _thread = new Thread(RequestThread){IsBackground = true};
    }
    
    public void Start()
    {
        Log.Info("Listening on port 8011");
        _listener.Start();
        _thread.Start();
    }

    private void RequestThread()
    {
        while (_thread.ThreadState != ThreadState.Stopped)
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