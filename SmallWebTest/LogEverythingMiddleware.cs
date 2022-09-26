using Microsoft.AspNetCore.Http.Extensions;

namespace SmallWebTest;

public class LogEverythingMiddleware
{
    private readonly RequestDelegate _next;

    public LogEverythingMiddleware(RequestDelegate next)
    {
        _next = next;
    }
    
    public async Task Invoke(HttpContext context)
    {
        var url = context.Request.GetEncodedUrl().ToLowerInvariant();
        Console.WriteLine($"Request: {url}; {context.Request.Host}");
        
        await _next(context);
    }
}