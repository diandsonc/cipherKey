using Microsoft.AspNetCore.Authentication;

namespace CipherKey
{
    /// <summary>
    /// Options for the 'CipherKeyScheme' authentication.
    /// </summary>
    public class CipherKeySchemeOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Gets or sets the name of the header or query parameter of the API Key.
        /// </summary>
        public string? KeyName { get; set; } = CipherKeyDefaults.KeyName;

        /// <summary>
        /// Gets or sets the default key to check, following the default 'ownner://apiKey'.
        /// </summary>
        public string? ApiKey { get; set; }
    }
}
