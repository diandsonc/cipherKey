namespace CipherKey;

/// <summary>
/// Default values used by the CipherKey authentication.
/// </summary>
public static class CipherKeyDefaults
{
    /// <summary>
    /// The default authentication scheme for ApiKey.
    /// </summary>
    public const string AuthenticationScheme = "ApiKey";

    /// <summary>
    /// The default name of the header or query parameter containing the API key.
    /// </summary>
    public const string KeyName = "X-API-Key";
}
