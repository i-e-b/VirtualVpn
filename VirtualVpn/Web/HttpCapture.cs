using System.Net;
using System.Text;
using SkinnyJson;
using Tag;

namespace VirtualVpn.Web;

public class HttpCapture
{
    private readonly HttpListener _listener;
    private readonly Thread _listenThread;
    private volatile bool _running;

    public HttpCapture()
    {
        _listener = new HttpListener();
        _listener.IgnoreWriteExceptions = true;

        _listener.Prefixes.Add("http" + Settings.HttpPrefix);
        
        _listenThread = new Thread(ListenThreadLoop){IsBackground = true}; 
    }
    
    public void Start()
    {
        Log.Info("Starting API");
        _running = true;
        _listener.Start();
        _listenThread.Start();
    }
    
    public void Stop()
    {
        _running = false;
        _listener.Stop();
    }

    private void ListenThreadLoop()
    {
        Log.Info($"API Listening on {string.Join(" | ", _listener.Prefixes.Select(p => p))}");
        while (_running)
        {
            
            HttpListenerContext? ctx = null;
            try
            {
                ctx = _listener.GetContext();

                var url = ctx.Request.RawUrl ?? "<null>";
                Log.Debug($"HTTP listener responding to {url}");

                if (IsApi(url))
                {
                    HandleApiRequest(url, ctx);
                }
                else if (Settings.RunAirliftSite)
                {
                    HandleAirliftRequest(url, ctx);
                }
                // Ignore anything else
                
                ctx.Response.Close();
                ctx = null;
            }
            catch (Exception ex)
            {
                Log.Error("Failure in HTTP handler", ex);
                TryCloseContext(ctx);
                Thread.Sleep(1000);
            }
        }
    }

    /// <summary>
    /// Respond to API requests
    /// </summary>
    private void HandleApiRequest(string url, HttpListenerContext ctx)
    {
        
        var cmd = url.Substring(5); // trim off '/api/'
        switch (cmd)
        {
            case "send":
                // should have a JSON body with:
                // - target IP (at far end of VPN tunnel)
                // - proxy IP (in the Virtual VPN)
                // - body of call (e.g. entire HTTP headers & body, as required)
                var ok = HandleProxyCall(ctx);
                if (!ok) goto default;
                return;
            
            default:
                Log.Warn($"Unknown command '{cmd}'");
                var bytes = ShowApiInfoPage();
                ctx.Response.StatusCode = 450;
                ctx.Response.StatusDescription = "Blocked by Windows Parental Controls";
                ctx.Response.AddHeader("Content-Type", "text/html");
                ctx.Response.OutputStream.Write(bytes);
                ctx.Response.OutputStream.Flush();
                return;
        }
    }

    /// <summary>
    /// Make a HTTP call from a remote location
    /// as-if the call originated from a node inside
    /// the VirtualVPN.
    /// <p></p>
    /// This should have a JSON body with:
    /// <ul><li>target IP (at far end of VPN tunnel)</li>
    ///     <li>proxy IP (in the Virtual VPN)</li>
    ///     <li>body of call (e.g. entire HTTP headers and body, as required)</li>
    /// </ul>
    /// </summary>
    private static bool HandleProxyCall(HttpListenerContext ctx)
    {
        Log.Trace("Reading proxy request");
        var keyHash = ctx.Request.Headers.Get("X-Api-Key"); // Hash output of timestamp + ApiKey
        var timestamp = ctx.Request.Headers.Get("X-Api-TS"); // Caller's claimed local time (UTC, in ticks, base64)

        if (keyHash is null || timestamp is null)
        {
            Log.Info("Proxy request with invalid headers");
            return false;
        }

        var ms = new MemoryStream();
        ctx.Request.InputStream.CopyTo(ms);
        ms.Seek(0, SeekOrigin.Begin);
        var bodyCipherText = ms.ToArray();

        var finalOutput = HandleProxyCallInternal(Settings.ApiKey, keyHash, timestamp, bodyCipherText, rq => Program.VpnServer?.MakeProxyCall(rq));
        if (finalOutput is null)
        {
            Log.Trace("Proxy request internal handler rejected call");
            return false;
        }

        ctx.Response.StatusCode = 200;
        ctx.Response.StatusDescription = "Processed";
        ctx.Response.ContentType = "application/octet-stream";
        ctx.Response.ContentLength64 = finalOutput.Length;
        ctx.Response.OutputStream.Write(finalOutput);
        ctx.Response.OutputStream.Flush();
        
        Log.Trace($"Proxy request complete: {finalOutput.Length} bytes");
        return true;
    }

    /// <summary>
    /// Handler for testing. Do not call
    /// </summary>
    public static byte[]? HandleProxyCallInternal(string keyGen, string keyHash, string timestamp, byte[] bodyCipherText, Func<HttpProxyRequest, HttpProxyResponse?> core)
    {
        var cipher = new ProxyCipher(keyGen, timestamp);
        if (!cipher.IsValidCall(keyHash))
        {
            Log.Debug("Proxy call: header keys invalid");
            return null;
        }

        Log.Trace("Decrypting request");
        var bodyString = cipher.Decode(bodyCipherText);
        var request = Json.Defrost<HttpProxyRequest>(bodyString);

        var response = core(request);
        if (response is null)
        {
            Log.Debug("Proxy call: core returned null");
            return null;
        }

        Log.Trace("Encrypting response");
        var finalOutput = cipher.Encode(Json.Freeze(response));
        return finalOutput;
    }

    /// <summary>
    /// Allow files stored in <see cref="Settings.FileBase"/>
    /// to be read remotely. Traffic capture files will be
    /// written here if enabled.
    /// </summary>
    private static void HandleAirliftRequest(string url, HttpListenerContext ctx)
    {
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
    }
    
    /// <summary>
    /// Show a basic greeting message for the API
    /// </summary>
    private static byte[] ShowApiInfoPage()
    {
        var head = T.g("head")[
            T.g("title")["VirtualVPN - API"]
        ];

        var body = T.g("body")[
            T.g("h1")["Virtual VPN"],
            T.g("p")["This is a VirtualVPN instance"],
            T.g("p")[
                "You have successfully connected to the API interface. ",
                "You will need to provide your API keys in request headers. ",
                "See documentation for details. "
            ]
        ];

        var document = T.g("html")[
            head,
            body
        ];

        return document.ToBytes(Encoding.UTF8);
    }

    /// <summary>
    /// Show a basic error message if an Airlift
    /// file is not found
    /// </summary>
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

    /// <summary>
    /// Show the index page for Airlift.
    /// This lists out the files that can
    /// be extracted, along with links.
    /// </summary>
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
    

    private bool IsApi(string url)
    {
        return url.StartsWith("/api/");
    }

    private static void TryCloseContext(HttpListenerContext? ctx)
    {
        try
        {
            ctx?.Response.Close();
        }
        catch
        {
            // ignore
        }
    }
}