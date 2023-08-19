using CipherKey.Events;
using Microsoft.AspNetCore.Authentication;

namespace CipherKey
{
    /// <summary>
    /// Options for the 'CipherKeyScheme' authentication.
    /// </summary>
    public class CipherKeySchemeOptions : AuthenticationSchemeOptions
    {
        public CipherKeySchemeOptions()
        {
            Events = new CipherKeyEvents();
        }

        /// <summary>
        /// Gets or sets the name of the header or query parameter of the API Key.
        /// </summary>
        public string? KeyName { get; set; } = CipherKeyDefaults.KeyName;

        /// <summary>
        /// Gets or sets the default key to check, following the default 'ownner://apiKey'.
        /// </summary>
        public string? ApiKey { get; set; }

        /// <summary>
        /// Gets or sets the object provided by the application to process events raised by the API key 
        /// authentication middleware.
        /// </summary>
        public new CipherKeyEvents? Events
        {
            get => (CipherKeyEvents?)base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Gets or sets the type of the API key provider.
        /// </summary>
        internal Type? ApiKeyProviderType { get; set; }
    }
}
