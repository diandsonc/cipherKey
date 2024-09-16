using System.Net.Http.Headers;
using System.Text.Encodings.Web;
using CipherKey.Events;
using CipherKey.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace CipherKey
{
    /// <summary>
    /// Handles API key authentication using the CipherKey scheme.
    /// Inherited from <see cref="AuthenticationHandler{TOptions}"/>.
    /// </summary>
    public class CipherKeyHandler : AuthenticationHandler<CipherKeySchemeOptions>
    {
        private readonly ICorsService _corsService;
        private readonly ICorsPolicyProvider _corsPolicyProvider;

        public CipherKeyHandler(IOptionsMonitor<CipherKeySchemeOptions> options, ILoggerFactory logger,
            UrlEncoder encoder, ICorsService corsService, ICorsPolicyProvider corsPolicyProvider)
            : base(options, logger, encoder)
        {
            _corsService = corsService;
            _corsPolicyProvider = corsPolicyProvider;
        }

        /// <summary>
        /// Get or set <see cref="CipherKeyEvents"/>.
        /// </summary>
        protected new CipherKeyEvents? Events { get => (CipherKeyEvents?)base.Events; set => base.Events = value; }

        /// <summary>
        /// Handles authentication for the CipherKey scheme.
        /// </summary>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            try
            {
                await ParseOriginAsync().ConfigureAwait(false);
            }
            catch (Exception originException)
            {
                return HandleError("Origin", originException);
            }

            try
            {
                var validatedApiCors = await ValidateCorsAsync().ConfigureAwait(false);
                if (validatedApiCors is not null)
                {
                    return validatedApiCors;
                }
            }
            catch (Exception corsException)
            {
                return HandleError("Cors", corsException);
            }

            string? apiKey = await ParseApiKeyAsync().ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(apiKey))
            {
                Logger.LogDebug("No Api Key found in the request.");
                return AuthenticateResult.NoResult();
            }

            try
            {
                var validateEventResult = await ValidateUsingEventAsync(apiKey).ConfigureAwait(false);
                if (validateEventResult is not null)
                {
                    return validateEventResult;
                }

                var validateConfigKeyResult = await ValidateConfigKeyAsync(apiKey).ConfigureAwait(false);
                if (validateConfigKeyResult is not null)
                {
                    return validateConfigKeyResult;
                }

                var validatedApiKey = await ValidateUsingApiKeyProviderAsync(apiKey).ConfigureAwait(false);
                if (validatedApiKey is not null)
                {
                    if (apiKey.Contains("://"))
                    {
                        var apiKeyParts = apiKey.Split("://", StringSplitOptions.RemoveEmptyEntries);
                        if (apiKeyParts.Length == 2)
                        {
                            return ValidateApiKeyDetails(validatedApiKey, apiKeyParts[1]);
                        }
                    }

                    return ValidateApiKeyDetails(validatedApiKey, apiKey);
                }

                return HandleError("API Key", new InvalidOperationException("Invalid API Key provided."));
            }
            catch (Exception)
            {
                throw; // Re-throw the exception to avoid swallowing it
            }
        }

        private AuthenticateResult HandleError(string errorLocation, Exception exception)
        {
            Logger.LogError(exception, $"Error {errorLocation}.");
            return AuthenticateResult.Fail($"Error {errorLocation}." + Environment.NewLine + exception.Message);
        }

        private Task<string?> ParseApiKeyAsync()
        {
            if (string.IsNullOrWhiteSpace(Options.KeyName))
            {
                return Task.FromResult<string?>(null);
            }

            if (Request.Headers.TryGetValue(Options.KeyName, out var headerValue))
            {
                return Task.FromResult(headerValue.FirstOrDefault());
            }

            if (Request.Query.TryGetValue(Options.KeyName, out var queryValue))
            {
                return Task.FromResult(queryValue.FirstOrDefault());
            }

            if (Request.Headers.TryGetValue(HeaderNames.Authorization, out var authHeaderValues) &&
                AuthenticationHeaderValue.TryParse(authHeaderValues, out var authHeaderValue) &&
                authHeaderValue.Scheme.Equals(Options.KeyName, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(authHeaderValue.Parameter);
            }

            return Task.FromResult<string?>(null);
        }

        private async Task<AuthenticateResult?> ValidateUsingEventAsync(string apiKey)
        {
            if (Events is null || Events.OnValidateKey is null)
            {
                return null;
            }

            var validateKeyContext = new ValidateKeyContext(Context, Scheme, Options, apiKey);
            await Events.ValidateKeyAsync(validateKeyContext).ConfigureAwait(false);

            return validateKeyContext.Result;
        }

        private Task<AuthenticateResult?> ValidateConfigKeyAsync(string apiKey)
        {
            if (string.IsNullOrWhiteSpace(Options.ApiKey))
            {
                return Task.FromResult<AuthenticateResult?>(null);
            }

            var validateKeyContext = new ValidateKeyContext(Context, Scheme, Options, apiKey);
            if (string.Equals(validateKeyContext.ApiKey, Options.ApiKey, StringComparison.OrdinalIgnoreCase))
            {
                validateKeyContext.ValidationSucceeded(validateKeyContext.Owner);
                return Task.FromResult<AuthenticateResult?>(validateKeyContext.Result);
            }

            return Task.FromResult<AuthenticateResult?>(null);
        }

        private async Task<IApiKey?> ValidateUsingApiKeyProviderAsync(string apiKey)
        {
            IApiKeyProvider? apiKeyProvider = null;

            if (Options.ApiKeyProviderType is not null)
            {
                apiKeyProvider = ActivatorUtilities
                    .GetServiceOrCreateInstance(Context.RequestServices, Options.ApiKeyProviderType)
                    as IApiKeyProvider;
            }

            if (apiKeyProvider is null)
            {
                return null;
            }

            try
            {
                var validateKeyContext = new ValidateKeyContext(Context, Scheme, Options, apiKey);

                return await apiKeyProvider
                    .ProvideAsync(validateKeyContext.ApiKey, validateKeyContext.Owner)
                    .ConfigureAwait(false);
            }
            finally
            {
                if (apiKeyProvider is IDisposable disposableApiKeyProvider)
                {
                    disposableApiKeyProvider.Dispose();
                }
            }
        }

        private AuthenticateResult ValidateApiKeyDetails(IApiKey validatedApiKey, string apiKey)
        {
            if (validatedApiKey.Origin is not null
                && !validatedApiKey.Origin.Contains(Request.Headers.Origin.ToString()))
            {
                return HandleError("Origin",
                    new InvalidOperationException(
                        $"Origin {Request.Headers.Origin} not allowed by {nameof(IApiKeyProvider)}."));
            }

            if (!string.Equals(validatedApiKey.Key, apiKey, StringComparison.OrdinalIgnoreCase))
            {
                return HandleError("API Key Provider",
                    new InvalidOperationException($"Invalid API Key provided by {nameof(IApiKeyProvider)}."));
            }

            var principal = CipherKeyUtils
                .BuildPrincipal(validatedApiKey.OwnerName, Scheme.Name, ClaimsIssuer, Options.Scope);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }

        private async Task<AuthenticateResult?> ValidateCorsAsync()
        {
            var validatedApiCors = new CorsContext(Context, Scheme, Options, _corsService, _corsPolicyProvider);
            await validatedApiCors.ValidateCorsAsync().ConfigureAwait(false);

            return validatedApiCors.Result;
        }

        private Task ParseOriginAsync()
        {
            if (Request.Headers.TryGetValue("Origin", out var _))
            {
                return Task.CompletedTask;
            }

            if (Request.Headers.TryGetValue("X-Origin", out var xOrigin))
            {
                Request.Headers.Origin = xOrigin;
                return Task.CompletedTask;
            }

            if (Request.Headers.TryGetValue("Referer", out var referer)
                && Uri.TryCreate(referer, UriKind.Absolute, out var uriOrigin))
            {
                var refererOrigin = uriOrigin.Port == 80 || uriOrigin.Port == 443
                    ? $"{uriOrigin.Scheme}://{uriOrigin.Host}"
                    : $"{uriOrigin.Scheme}://{uriOrigin.Host}:{uriOrigin.Port}";

                Request.Headers.Origin = refererOrigin;
                return Task.CompletedTask;
            }

            if (Request.Headers.TryGetValue("Postman-Token", out var _))
            {
                Request.Headers.Origin = "postman";
                return Task.CompletedTask;
            }

            var requestIp = Request.HttpContext.Connection.RemoteIpAddress?.ToString();
            if (!string.IsNullOrEmpty(requestIp))
            {
                Request.Headers.Origin = requestIp;
                return Task.CompletedTask;
            }

            Request.Headers.Origin = "unknown";
            return Task.CompletedTask;
        }
    }
}
