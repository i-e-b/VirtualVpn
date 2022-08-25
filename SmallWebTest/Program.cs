using SmallWebTest;
using SmallWebTest.Controllers;

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

// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI();

//app.UseHttpsRedirection(); // only for testing!

app.UseAuthorization();

app.UseRouter(new FallbackRouter());
app.MapControllers();


app.Run();