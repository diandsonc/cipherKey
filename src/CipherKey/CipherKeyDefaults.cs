namespace CipherKey
{
    /// <summary>
    /// Default values used by the CipherKey authentication.
    /// </summary>
    public static class CipherKeyDefaults
    {
        /// <summary>
        /// The default authentication scheme for CipherKey.
        /// </summary>
        public const string AuthenticationScheme = "CipherKey";

        /// <summary>
        /// The default name of the header or query parameter containing the API key.
        /// </summary>
        public const string KeyName = "X-API-Key";
    }
}
