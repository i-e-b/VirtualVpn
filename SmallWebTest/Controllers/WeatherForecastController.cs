using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace SmallWebTest.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
    }

    [HttpPost(template:"checksum", Name="Checksum data")]
    public IActionResult Checksum([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] byte[] data)
    {
        Console.WriteLine($"Data length = {data.Length}");
        
        return Content($"Read {data.Length} bytes. Checksum={BalancedHash(data):x8}", "text/plain");
    }
    
    UInt32 BalancedHash(byte[] str) {
        UInt32 len = (uint)str.Length;
        UInt32 hash = len;
        for (int i = 0; i < len; i++) {
            hash += str[i];
            hash ^= hash >> 16;
            hash *= 0x7feb352d;
            hash ^= hash >> 15;
            hash *= 0x846ca68b;
            hash ^= hash >> 16;
        }
        hash ^= len;
        hash ^= hash >> 16;
        hash *= 0x7feb352d;
        hash ^= hash >> 15;
        hash *= 0x846ca68b;
        hash ^= hash >> 16;
        hash += len;

        if (hash == 0) return 0x800800; // never return zero
        return hash;
    }
}