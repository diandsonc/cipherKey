using CipherKey;
using ProviderAuthenticationSample.Models;

namespace ProviderAuthenticationSample.Repositories
{
    public class MyCustomProvider : IApiKeyProvider
    {
        private readonly List<IApiKey> _cache = new List<IApiKey>
        {
            new ApiKey("cipher_key_provide_27", "Lagertha", new string[] { "http://localhost:5081" }),
            new ApiKey("cipher_key_provide_11", "Brandon", new string[] { "http://localhost:5000" }),
            new ApiKey("cipher_key_provide_88", "Rieka", new string[] { }), // Deny all origins
            new ApiKey("cipher_key_provide_35", "Adena") // Allow any origin 
        };

        public Task<IApiKey?> ProvideAsync(string key)
        {
            // Write your custom validation logic here.
            // Return an instance of a valid ApiKey or null for an invalid key.
            var apiKey = _cache.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(apiKey);
        }
    }
}
