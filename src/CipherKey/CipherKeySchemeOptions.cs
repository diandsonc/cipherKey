using CipherKey.Events;
using Microsoft.AspNetCore.Authentication;

namespace CipherKey;

/// <summary>
/// Options for the 'CipherKeyScheme' authentication.
/// </summary>
public class CipherKeySchemeOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CipherKeySchemeOptions"/> class.
    /// Sets default values for the properties, including initializing the <see cref="Events"/> to a new instance of <see cref="CipherKeyEvents"/>.
    /// </summary>
    public CipherKeySchemeOptions()
    {
        Events = new CipherKeyEvents();
    }

    /// <summary>
    /// Gets or sets the name of the header or query parameter of the API Key.
    /// </summary>
    public string? KeyName { get; set; } = CipherKeyDefaults.KeyName;

    /// <summary>
    /// Gets or sets the default key to check, following the default 'ownner://apiKey'.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Gets or sets the scope to be put on the claim.
    /// </summary>
    public string? Scope { get; set; }

    /// <summary>
    /// Gets or sets whether to use the fallback policy for every request by default.
    /// </summary>
    public bool UseFallbackPolicy { get; set; } = false;

    /// <summary>
    /// Gets or sets the allowed origins to check during CORS validation.
    /// </summary>
    public string[]? AllowOrigins { get; set; }

    /// <summary>
    /// Gets or sets the allowed methods to check during CORS validation.
    /// </summary>
    public string[]? AllowMethods { get; set; }

    /// <summary>
    /// Gets or sets the object provided by the application to process events raised by the API key 
    /// authentication middleware.
    /// </summary>
    public new CipherKeyEvents? Events
    {
        get => (CipherKeyEvents?)base.Events;
        set => base.Events = value;
    }

    /// <summary>
    /// Gets or sets the type of the API key provider.
    /// </summary>
    internal Type? ApiKeyProviderType { get; set; }

    /// <summary>
    /// Gets or sets the policy name when validating CORS.
    /// </summary>
    internal string? PolicyName { get; set; }
}
