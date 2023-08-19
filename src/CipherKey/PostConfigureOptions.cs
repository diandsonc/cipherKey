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
        }
    }
}
