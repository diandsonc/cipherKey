namespace CipherKey
{
    /// <summary>
    /// Represents API Key details.
    /// </summary>
    public interface IApiKey
    {
        /// <summary>
        /// Gets the API Key value.
        /// </summary>
        string Key { get; }

        /// <summary>
        /// Gets the owner of the API Key. This can be a username or any other key owner name.
        /// </summary>
        string OwnerName { get; }

        /// <summary>
        /// Gets the URIs that are accepted as destinations when returning authentication responses (tokens)
        /// after successfully authenticating or signing out users.
        /// </summary>
        string[]? Origin { get; }
    }
}
