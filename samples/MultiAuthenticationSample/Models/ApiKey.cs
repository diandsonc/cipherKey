using CipherKey;

namespace MultiAuthenticationSample.Models
{
    public class ApiKey : IApiKey
    {
        public ApiKey(string key, string owner, string[]? origin = null)
        {
            Key = key;
            OwnerName = owner;
            Origin = origin;
        }

        public string Key { get; set; }

        public string OwnerName { get; set; }

        public string[]? Origin { get; set; }
    }
}
