using CipherKey;
using Microsoft.AspNetCore.Authentication;
using ProviderAuthenticationSample.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.Configure<RouteOptions>(options => { options.LowercaseUrls = true; });

builder.Services.AddCipherKey<MyCustomProvider>(CipherKeyDefaults.AuthenticationScheme, op => {
   
});

var app = builder.Build();

app.MapControllers();

app.UseCipherKey();

app.Run();
