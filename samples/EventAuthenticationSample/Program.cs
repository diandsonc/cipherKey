using CipherKey;
using CipherKey.Events;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.Configure<RouteOptions>(options => { options.LowercaseUrls = true; });

builder.Services.AddCipherKey(CipherKeyDefaults.AuthenticationScheme, options =>
{
    options.Events = new CipherKeyEvents
    {
        OnValidateKey = context =>
        {
            if (context.ApiKey == "cipher_key_event")
            {
                context.ValidationSucceeded(ownerName: "Lagertha");
            }
            else
            {
                context.ValidationFailed();
            }

            return Task.CompletedTask;
        }
    };
});

var app = builder.Build();

app.MapControllers();

app.UseCipherKey();

app.Run();
