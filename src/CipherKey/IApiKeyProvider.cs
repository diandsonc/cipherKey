namespace CipherKey
{
    /// <summary>
    /// Represents the contract for a provider used by the 'CipherKey' authentication handler to 
    /// validate keys and retrieve key details.
    /// </summary>
    public interface IApiKeyProvider
    {
        /// <summary>
        /// Validates the provided key and returns an instance of <see cref="IApiKey"/>.
        /// </summary>
        /// <param name="key">The API key to validate.</param>
        /// <param name="owner">The API key owner to validate.</param>
        /// <returns>An instance of <see cref="IApiKey"/> if validation is successful; 
        /// otherwise, returns null.</returns>
        Task<IApiKey?> ProvideAsync(string key, string? owner = null);
    }
}
