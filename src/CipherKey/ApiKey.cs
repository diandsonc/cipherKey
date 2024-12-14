namespace CipherKey;

/// <summary>
/// Represents API Key details.
/// </summary>
public record ApiKey
{
    /// <summary>
    /// Gets the API Key value.
    /// </summary>
    public string Key { get; init; }

    /// <summary>
    /// Gets the owner of the API Key. This can be a username or any other key owner name.
    /// </summary>
    public string OwnerName { get; init; }

    /// <summary>
    /// Gets the URIs that are accepted as destinations when returning authentication responses (tokens)
    /// after successfully authenticating or signing out users.
    /// </summary>
    public string[]? Origin { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ApiKey"/> record.
    /// </summary>
    /// <param name="key">The API key value.</param>
    /// <param name="ownerName">The owner of the API key.</param>
    /// <param name="origin">The accepted URIs for the API key.</param>
    public ApiKey(string key, string ownerName, string[]? origin = null)
    {
        Key = key;
        OwnerName = ownerName;
        Origin = origin;
    }
}
