using CipherKey;

namespace ProviderAuthenticationSample.Repositories
{
    public class MyCustomProvider : IApiKeyProvider
    {
        private readonly List<ApiKey> _cache = new()
        {
            new ApiKey("cipher_key_provide_27", "Lagertha", ["http://localhost:5081"]),
            new ApiKey("cipher_key_provide_11", "Brandon", ["http://localhost:5000"]),
            new ApiKey("cipher_key_provide_88", "Rieka", []), // Deny all origins
            new ApiKey("cipher_key_provide_35", "Adena") // Allow any origin 
        };

        public Task<ApiKey?> ProvideAsync(string key, string? owner)
        {
            // Write your custom validation logic here.
            // Return an instance of a valid ApiKey or null for an invalid key.
            var apiKey = _cache.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

            return Task.FromResult(apiKey);
        }
    }
}
