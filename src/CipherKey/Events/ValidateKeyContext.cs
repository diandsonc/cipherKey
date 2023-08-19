using CipherKey.Utils;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace CipherKey.Events
{
    /// <summary>
    /// Context used for validating the API key.
    /// </summary>
    public class ValidateKeyContext : ResultContext<CipherKeySchemeOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ValidateKeyContext"/> class.
        /// </summary>
        /// <param name="context">The HTTP context.</param>
        /// <param name="scheme">The authentication scheme.</param>
        /// <param name="options">The authentication options.</param>
        /// <param name="apiKey">The API key to validate.</param>
        public ValidateKeyContext(HttpContext context, AuthenticationScheme scheme, CipherKeySchemeOptions options,
            string apiKey)
            : base(context, scheme, options)
        {
            ApiKey = apiKey;
        }

        /// <summary>
        /// Gets the API key being validated.
        /// </summary>
        public string ApiKey { get; }

        /// <summary>
        /// Handles the successful validation of the API key.
        /// </summary>
        /// <param name="ownerName">The owner name to be added to claims as <see cref="ClaimTypes.Name"/> 
        /// and <see cref="ClaimTypes.NameIdentifier"/> if not already added with <paramref name="claims"/>.</param>
        public void ValidationSucceeded(string ownerName)
        {
            Principal = CipherKeyUtils.BuildPrincipal(ownerName, Scheme.Name, Options.ClaimsIssuer ?? "", Options.Scope);
            Success();
        }

        /// <summary>
        /// Handles the failed validation of the API key.
        /// </summary>
        /// <param name="failureMessage">(Optional) The failure message.</param>
        public void ValidationFailed(string? failureMessage = null)
        {
            if (string.IsNullOrWhiteSpace(failureMessage))
            {
                NoResult();
                return;
            }

            Fail(failureMessage);
        }
    }
}
