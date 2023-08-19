using Microsoft.Extensions.Options;

namespace CipherKey
{
    /// <summary>
    /// Post-configure options checks whether the required option properties are 
    /// set on <see cref="CipherKeySchemeOptions"/>.
    /// </summary>
    internal class PostConfigureOptions : IPostConfigureOptions<CipherKeySchemeOptions>
    {
        /// <inheritdoc />
        public void PostConfigure(string? name, CipherKeySchemeOptions options)
        {
            if (string.IsNullOrWhiteSpace(options.KeyName))
            {
                throw new InvalidOperationException(
                    @$"{nameof(CipherKeySchemeOptions.KeyName)} must 
                    be set in {typeof(CipherKeySchemeOptions).Name} when setting up the authentication."
                );
            }

            if (options.ApiKey is null
                && options.Events?.OnValidateKey is null
                && options.EventsType is null
                && options.ApiKeyProviderType is null)
            {
                throw new InvalidOperationException(
                    @$"{nameof(CipherKeySchemeOptions.ApiKey)} should 
                    be set or {nameof(CipherKeySchemeOptions.Events.OnValidateKey)} should 
                    be delegated in configure options {nameof(CipherKeySchemeOptions.Events)}, 
                    or use an extension method with a type parameter of type {nameof(IApiKeyProvider)}."
                );
            }
        }
    }
}
