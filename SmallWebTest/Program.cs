using SmallWebTest.Controllers;

namespace SmallWebTest;

class Program
{
    public static void Main(string[] args)
    {
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Console.WriteLine("Unobserved exception: {0}", e.Exception);
        };

        AppDomain.CurrentDomain.UnhandledException += CurrentDomainOnUnhandledException;

        var builder = WebApplication.CreateBuilder(args);


// Add services to the container.

        builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();
        builder.Services.AddMvc(options =>
        {
            options.InputFormatters.Insert(0, new BinaryInputFormatter());
        });

        var app = builder.Build();

        app.UseMiddleware<LogEverythingMiddleware>();

// Configure the HTTP request pipeline.
        app.UseSwagger();
        app.UseSwaggerUI();

//app.UseHttpsRedirection(); // only for testing!

        app.UseAuthorization();

        app.UseRouter(new FallbackRouter());
        app.MapControllers();


        app.Run();
    }

    private static void CurrentDomainOnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        Console.WriteLine("Unobserved exception: " + e.ExceptionObject);
    }
}