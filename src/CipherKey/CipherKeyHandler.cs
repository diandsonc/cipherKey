using System.Net.Http.Headers;
using System.Text.Encodings.Web;
using CipherKey.Events;
using CipherKey.Utils;
using Microsoft.AspNetCore.Authentication;
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
        public CipherKeyHandler(IOptionsMonitor<CipherKeySchemeOptions> options, ILoggerFactory logger,
            UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
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
            if (validateKeyContext.ApiKey.Contains("://"))
            {
                var apiKeyParts = validateKeyContext.ApiKey.Split("://", StringSplitOptions.RemoveEmptyEntries);

                if (apiKeyParts.Length == 2)
                {
                    var ownerName = apiKeyParts[0];
                    var validatedApiKey = apiKeyParts[1];

                    if (string.Equals(validatedApiKey, Options.ApiKey, StringComparison.OrdinalIgnoreCase))
                    {
                        validateKeyContext.ValidationSucceeded(ownerName);
                        return Task.FromResult<AuthenticateResult?>(validateKeyContext.Result);
                    }
                }
            }

            return Task.FromResult<AuthenticateResult?>(null);
        }

        private async Task<IApiKey?> ValidateUsingApiKeyProviderAsync(string apiKey)
        {
            IApiKeyProvider? apiKeyProvider = null;

            if (Options.ApiKeyProviderType is not null)
            {
                apiKeyProvider = ActivatorUtilities
                    .GetServiceOrCreateInstance(Context.RequestServices, Options.ApiKeyProviderType) as IApiKeyProvider;
            }

            if (apiKeyProvider is null)
            {
                return null;
            }

            try
            {
                return await apiKeyProvider.ProvideAsync(apiKey).ConfigureAwait(false);
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
            if (!string.Equals(validatedApiKey.Key, apiKey, StringComparison.OrdinalIgnoreCase))
            {
                return HandleError("API Key Provider",
                    new InvalidOperationException($"Invalid API Key provided by {nameof(IApiKeyProvider)}."));
            }

            var principal = CipherKeyUtils
                .BuildPrincipal(validatedApiKey.OwnerName, Scheme.Name, ClaimsIssuer);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}
