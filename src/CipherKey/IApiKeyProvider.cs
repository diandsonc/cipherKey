namespace CipherKey;

/// <summary>
/// Represents the contract for a provider used by the 'CipherKey' authentication handler to 
/// validate keys and retrieve key details.
/// </summary>
public interface IApiKeyProvider
{
    /// <summary>
    /// Validates the provided key and returns an instance of <see cref="ApiKey"/>.
    /// </summary>
    /// <param name="key">The API key to validate.</param>
    /// <param name="owner">The API key owner to validate. If not provided, validation is performed on the key alone.</param>
    /// <returns>An instance of <see cref="ApiKey"/> if validation is successful; 
    /// otherwise, returns null. If validation fails, <c>null</c> is returned.</returns>
    Task<ApiKey?> ProvideAsync(string key, string? owner = null);
}
