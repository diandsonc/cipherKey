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
    }
}
