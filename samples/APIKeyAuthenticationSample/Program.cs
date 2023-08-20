using CipherKey;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.Configure<RouteOptions>(options => { options.LowercaseUrls = true; });

builder.Services.AddCipherKey(CipherKeyDefaults.AuthenticationScheme, options =>
{
    options.ApiKey = "cipher_key_basic";
});

var app = builder.Build();

app.MapControllers();

app.UseCipherKey();

app.Run();
