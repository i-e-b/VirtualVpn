using System.Text;
using Microsoft.AspNetCore.Http.Extensions;

namespace SmallWebTest;

public class FallbackRouter : IRouter
{
    public Task RouteAsync(RouteContext context)
    {
        var url = context.HttpContext.Request.GetEncodedUrl().ToLowerInvariant();
        Console.WriteLine($"Request: {url}");
        
        // if it's a known path, return without adding a request handler
        if (url.Contains("/swagger/") || url.Contains("/weather")) return Task.CompletedTask;
        
        // if a handler is already bound, use that
        if (context.Handler is not null) return Task.CompletedTask;
        
        // Otherwise, bind our fall-back handler
        context.Handler = FallbackHandler;
        
        return Task.CompletedTask;
    }

    /// <summary>
    /// Give a basic message to any request
    /// </summary>
    private async Task FallbackHandler(HttpContext context)
    {
        context.Response.Headers.ContentType = "text/html";
        await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes(@"<html>
<head><title>Fallback</title></head>
<body>
<h1>Hello</h1>
<p>If you can see this message, you have successfully connected to the test server!</p>
<p>Try visiting the Swagger UI and test API use at <a href=""/swagger/index.html"">/swagger/index.html</a></p>
"));
        
        // Big transfer test
        var url = context.Request.GetEncodedUrl().ToLowerInvariant();
        if (url.Contains("/huge"))
        {
            for (int i = 0; i < 1000; i++)
            {
                await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes("I know a song that will get on your nerves, get on your nerves, get on your nerves.<br/>\r\n"));
            }
        }
        
        await context.Response.Body.WriteAsync(Encoding.UTF8.GetBytes("</body></html>\r\n"));
    }

    public VirtualPathData? GetVirtualPath(VirtualPathContext context)
    {
        return null;
    }
}