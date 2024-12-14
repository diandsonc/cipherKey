using System.Text;
using CipherKey;
using CipherKey.Events;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MultiAuthenticationSample.Repositories;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddHealthChecks();
builder.Services.AddControllers();
builder.Services.Configure<RouteOptions>(options => { options.LowercaseUrls = true; });
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    var baseUri = Environment.GetEnvironmentVariable("MSAL_INSTANCE") + Environment.GetEnvironmentVariable("MSAL_TENANT_ID");
    var scopeUrl = Environment.GetEnvironmentVariable("MSAL_API_SCOPE_URL") + "";
    var scope = Environment.GetEnvironmentVariable("MSAL_API_SCOPE") + "";

    var msalSecurityScheme = new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a **valid** token!",
        Name = "oauth2",
        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            Implicit = new OpenApiOAuthFlow()
            {
                AuthorizationUrl = new Uri(baseUri + "/oauth2/v2.0/authorize"),
                TokenUrl = new Uri(baseUri + "/oauth2/v2.0/token"),
                Scopes = new Dictionary<string, string> { { scopeUrl, scope } }
            }
        },
        Scheme = "oauth2"
    };

    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a **valid** token!",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = JwtBearerDefaults.AuthenticationScheme
    };

    var apiKeySecurityScheme = new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a **valid** Api Key with format _**system-name://api-key**_!",
        Name = "X-API-Key",
        Type = SecuritySchemeType.ApiKey,
        Scheme = CipherKeyDefaults.AuthenticationScheme
    };

    msalSecurityScheme.Reference = new OpenApiReference
    {
        Id = msalSecurityScheme.Scheme,
        Type = ReferenceType.SecurityScheme
    };

    jwtSecurityScheme.Reference = new OpenApiReference
    {
        Id = jwtSecurityScheme.Scheme,
        Type = ReferenceType.SecurityScheme
    };

    apiKeySecurityScheme.Reference = new OpenApiReference
    {
        Id = apiKeySecurityScheme.Scheme,
        Type = ReferenceType.SecurityScheme
    };

    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Thoth2 Demo auth API", Version = "v1" });
    options.AddSecurityDefinition(msalSecurityScheme.Reference.Id, msalSecurityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement { { msalSecurityScheme, new string[] { } } });
    options.AddSecurityDefinition(jwtSecurityScheme.Reference.Id, jwtSecurityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement { { jwtSecurityScheme, new string[] { } } });
    options.AddSecurityDefinition(apiKeySecurityScheme.Reference.Id, apiKeySecurityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement { { apiKeySecurityScheme, new string[] { } } });
});

builder.Services.AddCipherKey<MyCustomProvider>(CipherKeyDefaults.AuthenticationScheme, options =>
{
    var origins = Environment.GetEnvironmentVariable("API_CORS_ORIGINS") ?? "*";
    var methods = Environment.GetEnvironmentVariable("API_CORS_METHODS") ?? "*";

    options.ApiKey = Environment.GetEnvironmentVariable("API_KEY");
    options.ClaimsIssuer = Environment.GetEnvironmentVariable("TOKEN_ISSUER");
    options.Scope = "CiperKeyApi";
    options.AllowOrigins = origins.Split(',', StringSplitOptions.RemoveEmptyEntries);
    options.AllowMethods = methods.Split(',', StringSplitOptions.RemoveEmptyEntries);
    options.UseFallbackPolicy = true;
    options.Events = new CipherKeyEvents
    {
        OnValidateKey = context =>
        {
            if (context.ApiKey == "cipher_key_event")
            {
                context.ValidationSucceeded(ownerName: "Lagertha");
            }

            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthentication()
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        options.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = Environment.GetEnvironmentVariable("TOKEN_ISSUER"),
            ValidAudience = Environment.GetEnvironmentVariable("TOKEN_AUDIENCE"),
            IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("TOKEN_KEY") ?? ""))
        };
    })
    .AddMicrosoftIdentityWebApi(options => { }, options =>
    {
        options.ClientId = Environment.GetEnvironmentVariable("MSAL_CLIENT_ID");
        options.TenantId = Environment.GetEnvironmentVariable("MSAL_TENANT_ID");
        options.Instance = Environment.GetEnvironmentVariable("MSAL_INSTANCE") + "";
    }, "oauth2");

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
    });
});

builder.Services.AddAuthorizationBuilder()
    .SetDefaultPolicy(new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(CipherKeyDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build())
    .AddPolicy("jwtPolicy", new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build())
    .AddPolicy("msalPolicy", new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes("oauth2")
        .RequireAuthenticatedUser()
        .Build())
    .AddPolicy("apiKeyPolicy", new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(CipherKeyDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build())
    .AddPolicy("anyAuthPolicy", new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(
            JwtBearerDefaults.AuthenticationScheme,
            CipherKeyDefaults.AuthenticationScheme,
            "oauth2")
        .RequireAuthenticatedUser()
        .Build());

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.OAuthClientId(Environment.GetEnvironmentVariable("MSAL_CLIENT_ID"));
        c.OAuthClientSecret(Environment.GetEnvironmentVariable("MSAL_CLIENT_SECRET_SWAGGER"));
        c.OAuthUseBasicAuthenticationWithAccessCodeGrant();
    });
}

app.UseCors();

// app.UseHttpsRedirection();
app.MapControllers();

app.UseCipherKey();

app.MapHealthChecks("/healthcheck").AllowAnonymous();

app.Run();
