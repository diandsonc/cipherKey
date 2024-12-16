<p align="center">
  <img src="icon.png" alt="CipherKey" width="92">
  <h3 align="center">CipherKey</h3>
  <p align="center">API Key Authentication System</p>
</p>

## Status

[![NuGet Version](https://img.shields.io/nuget/v/cipherkey.svg)](https://img.shields.io/nuget/v/cipherkey.svg)
[![NuGet Downloads](https://img.shields.io/nuget/dt/cipherkey.svg)](https://www.nuget.org/packages/cipherkey)

# CipherKey: API Key Authentication System

CipherKey is a robust authentication system designed to secure your APIs using API keys. It provides a seamless and secure way to authenticate users and applications accessing your API endpoints. With CipherKey, you can ensure that only authorized entities can access your valuable resources, enhancing security and control over your API ecosystem.

## Features

- **Secure Communication**: Enhance the security of your API endpoints by requiring valid API keys, significantly reducing the risk of unauthorized access.

- **Easy Integration**: Seamlessly incorporate CipherKey into your existing API infrastructure with minimal code modifications, ensuring a hassle-free integration process.

- **CORS Control**: Exercise granular control over the origin of API requests, effectively preventing abuse and improper usage by specifying allowed origins.

- **Developer-Friendly**: Provide developers with a user-friendly and efficient means to securely access your API resources, promoting a positive development experience.

- **API Key Generation**: Generate distinct and unique API keys for each authorized user or application, allowing for fine-grained access control.

- **Secret Key Generation**: Create individual secret keys for each application, bolstering security measures and ensuring isolated access.

- **Data Encryption**: Strengthen security by encrypting sensitive data, offering an additional layer of protection against unauthorized access.

- **Data Decryption**: Decrypt encrypted data when needed, enabling authorized users to retrieve the original data while maintaining security standards.

## Getting Started

Follow these steps to integrate CipherKey into your API project:

1. **Installation**:

   - Install the CipherKey package from NuGet Package Manager:
     ```
     Install-Package CipherKey
     ```

2. **Integrate CipherKey**:

   - In your API routes or middleware, incorporate the CipherKey to validate incoming API keys.

3. **Configuration**:
   - In the `Program.cs` code snippet, set the validation options according to your specific requirements. This code should be placed in the startup logic of your application, such as the `Main` method in the `Program.cs` class.

Example C# code snippet for API key validation in `Program.cs`:

```csharp
using CipherKey;

// Inside your Program.cs

builder.Services.AddCipherKey<MyCustomProvider>(CipherKeyDefaults.AuthenticationScheme, options =>
{
    options.KeyName = "X-API-Key";
    options.ApiKey = "API_KEY";
    options.Scope = "api.scope";
    options.ClaimsIssuer = "TOKEN_ISSUER";
    options.AllowOrigins = new string[] { "http://localhost:4200", "http://localhost:5227" };
    options.AllowMethods = new string[] { "GET" };
    options.UseFallbackPolicy = true;
    options.Events = new CipherKeyEvents
    {
        OnValidateKey = context =>
        {
            if (context.ApiKey == "cipher_key_event")
            {
                context.ValidationSucceeded(ownerName: "Lagertha");
            }
            else
            {
                context.ValidationFailed();
            }

            return Task.CompletedTask;
        }
    };
});

builder.Services.AddHealthChecks();

// ... (other configurations)

// Enable CipherKey
app.UseCipherKey();

// Map health checks (allow anonymous access)
app.MapHealthChecks("/healthcheck").AllowAnonymous();

// ... (other middleware and configurations)
```

```csharp
// Inside your controller

public class MyController : Controller
{
    [Authorize]
    [HttpGet]
    public IActionResult Get() { }

    // Use this to validate the scope
    [Authorize]
    [RequiredScope("api.scope")]
    [HttpGet]
    public IActionResult GetScoped() { }

    // Use this to specify multiple schemes and scopes
    [Authorize(AuthenticationSchemes = "Bearer,ApiKey")]
    [RequiredScope("solutionName", "api.scope")]
    [HttpGet]
    public IActionResult GetMultiScheme() { }

    // Use this to validate a specific policy
    [Authorize(Policy = "anyAuth")]
    [HttpGet]
    public IActionResult GetPolicy() { }

    // Use the AllowAnonymous attribute to allow access
    // by non-authenticated users to specific actions
    [AllowAnonymous]
    [HttpGet]
    public IActionResult GetAllowAnonymous() { }
}
```

## API Key Validation Parameters

When integrating CipherKey into your application, consider the following parameters for API key validation:

- **KeyName**: Represents the name of the API key being used for authentication. It helps distinguish between different API keys and their associated permissions or roles. By default, the KeyName is "X-API-Key".

- **ApiKey**: The actual API key value that must be sent along with the request for authentication. It is used to validate the authenticity of the request.

- **Scope**: Defines the level of access or permissions associated with the API key. It specifies what actions or resources the API key holder is authorized to access.

- **ClaimsIssuer**: Specifies the issuer of the claims associated with the authentication token. It helps verify the authenticity of the token and ensures that it was issued by a trusted source.

- **UseFallbackPolicy**: Specifies whether to use the fallback policy for every request by default. When enabled, it challenges authentication for every request. Default value is `false`.

- **AllowOrigins**: Specifies the allowed origins for CORS. It defines which origins are permitted to make API requests, enhancing security and control over cross-origin requests.

- **AllowMethods**: Specifies the allowed HTTP methods for CORS. It defines which HTTP methods are allowed for cross-origin requests.

- **Events**: Provides hooks to attach custom logic or actions during the authentication process. Events can trigger actions such as success, failure.

Integrate these parameters according to your application's requirements to enhance the security and effectiveness of your API authentication process.

> **Important**
> The API key must be provided in the following format: `{owner}://{ApiKey}`. The `{owner}` placeholder refers to the owner or identifier of the API key, and `{ApiKey}` should be replaced with the actual API key value. If the API key is not provided in this exact format, authorizations will fail.

## Three Ways to Check the Key in the Request

CipherKey supports three methods to check the key provided in the request:

### A. Provider-Based Authentication

Provider-Based Authentication is a powerful method of API key validation that allows you to integrate with a custom provider to validate the provided API key. By using a provider, you can securely manage access tokens while considering the allowed origin. This approach is ideal for scenarios where you want to implement custom validation logic or manage key storage.

### Implementation Steps

1. #### Service Configuration:

In your application's `Program.cs` or `Startup.cs`` class, configure the CipherKey authentication to use your custom provider:

```csharp
using CipherKey;

// ...

builder.Services.AddCipherKey<MyCustomProvider>(CipherKeyDefaults.AuthenticationScheme);

```

2. #### Using CipherKey Middleware:

Add the `UseCipherKey` middleware in your application pipeline to enable API key authentication:

```csharp
app.UseCipherKey();
```

3. #### Custom Provider Implementation:

Create a custom provider class that implements the `IApiKeyProvider` interface. In this class, you will define the validation logic for API keys:

```csharp
using CipherKey;

public class MyCustomProvider : IApiKeyProvider
{
    private readonly List<ApiKey> _cache = new List<ApiKey>
    {
        new ApiKey("myApiKey27", "Lagertha", new string[] { "http://localhost:4200" }),
        new ApiKey("myApiKey11", "Brandon", new string[] { "http://localhost:5081" }),
        new ApiKey("myApiKey88", "Rieka", new string[] { }), // Deny all origins
        new ApiKey("myApiKey35", "Adena") // Allow any origin
    };

    public Task<ApiKey?> ProvideAsync(string key, string? owner)
    {
        // Write your custom validation logic here.
        // Return an instance of a valid ApiKey or null for an invalid key.
        var apiKey = _cache.FirstOrDefault(k => k.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

        return Task.FromResult(apiKey);
    }
}
```

#### Usage Considerations

Provider-Based Authentication is flexible and allows you to implement your own validation logic. This is particularly useful when you need to manage key storage, implement complex validation rules, or interact with external systems for key verification.

### B. Event-Based Authentication

Event-Based Authentication empowers you to inject custom logic and actions into the authentication process by utilizing events. This approach offers you the flexibility to trigger actions like token validation, user role checks, and logging, enhancing the customization and control of your authentication flow.

### Implementation Steps

1. #### Service Configuration:

In your application's `Program.cs` or `Startup.cs` class, configure the CipherKey authentication and define custom event logic:

```csharp
using CipherKey;

// ...

builder.Services.AddCipherKey(CipherKeyDefaults.AuthenticationScheme, options =>
{
    options.Events = new CipherKeyEvents
    {
        OnValidateKey = async context =>
        {
            // Custom validation logic
            var myKey = await myRepository.GetKey();

            if (context.ApiKey == myKey)
            {
                context.ValidationSucceeded(ownerName: "Lagertha");
            }
            else
            {
                // If you don't use ValidationFailed in case of failure,
                // the system will attempt to validate the key using your API_KEY and your provider
                context.ValidationFailed();
            }

            return Task.CompletedTask;
        }
    };
});

```

2. #### Using CipherKey Middleware:
   Integrate the `UseCipherKey` middleware into your application pipeline to activate the event-based authentication process:

```csharp
app.UseCipherKey();
```

#### Usage Considerations

Event-Based Authentication provides you with a powerful mechanism to customize the authentication process according to your application's specific requirements. By defining custom event logic, you can implement token validation, user role checks, and other actions that contribute to a secure and controlled authentication flow.

> **Note**
> If you implement custom event-based authentication using `OnValidateKey` and do not use `ValidationFailed` in case of a validation failure, the system will automatically attempt to validate the key using the API key configured (`options.ApiKey`) and your custom provider (`MyCustomProvider`), ensuring a seamless authentication process even when custom logic fails. To maintain full control over the validation process, make sure to use `ValidationFailed` appropriately when implementing custom validation logic.

### C. API Key-Based Authentication

API Key-Based Authentication provides a robust method to authenticate users and applications by utilizing unique API keys. This approach allows you to enforce controlled access to your API resources, providing enhanced security and granular control over your endpoints.

### Implementation Steps

1. #### Service Configuration:

In your application's `Program.cs` or `Startup.cs` class, configure the CipherKey authentication with the desired API key:

```csharp
using CipherKey;

// ...

builder.Services.AddCipherKey(CipherKeyDefaults.AuthenticationScheme, options =>
{
    options.ApiKey = "myApiKey";
});
```

2. #### Using CipherKey Middleware:

Integrate the `UseCipherKey` middleware into your application pipeline to activate API key authentication:

```csharp
app.UseCipherKey();
```

#### Usage Considerations

API Key-Based Authentication is a straightforward approach that suits scenarios where you need to authenticate users or applications based on unique API keys. You can further customize access control by specifying access levels, rate limits, and expiration for each API key, tailoring the authentication process to your application's needs.

## HTTP Request Examples

Here are examples of HTTP requests demonstrating different ways of including the `X-API-Key` parameter:

1. **Using Header Parameter `X-API-Key`**:

   - In this example, the API key is included in the request header as `X-API-Key`.

   ```bash
   curl -X GET "https://api.example.com/resource" -H "X-API-Key: YOUR_API_KEY_HERE"
   ```

2. **Using Query Parameter `X-API-Key`**:

   - In this example, the API key is included as a query parameter named `X-API-Key`.

   ```bash
   curl -X GET "https://api.example.com/resource?X-API-Key=YOUR_API_KEY_HERE"
   ```

3. **Using Authorization Header with `X-API-Key`**:

   - In this example, the API key is included in the `Authorization` header using the `X-API-Key` token format.

   ```bash
   curl -X GET "https://api.example.com/resource" -H "Authorization: X-API-Key YOUR_API_KEY_HERE"
   ```

In all of these examples, replace `https://api.example.com/resource` with the actual URL of your API endpoint, and `YOUR_API_KEY_HERE` with your valid API key. Choose the method that aligns with your API design and the way you've set up your authentication mechanism.

Remember to ensure that your CipherKey implementation is configured to validate the API key using the appropriate parameter name (`KeyName`) and that your API server is set up to handle the provided method of API key inclusion.

## CipherKey Manager

The CipherKey Manager provides convenient methods for managing API keys, generating secret encryption keys, and performing data encryption and decryption operations. Here's how to effectively use these methods:

#### Generating API Keys

To generate a new API key for your system, utilize the `GenerateApiKey` method with a meaningful identifier:

```csharp
string apiKey = CipherKeyManager.GenerateApiKey("mySystem");
```

### Generating Secret Encryption Keys

For secure data operations, generate secret encryption keys of specified lengths using the `GenerateSecretKey` method:

```csharp
string encryptionKey = CipherKeyManager.GenerateSecretKey(32); // 32-byte encryption key
string encryptionIV = CipherKeyManager.GenerateSecretKey(16); // 16-byte encryption IV
```

### Data Encryption and Decryption

Encrypt and decrypt sensitive data using CipherKey Manager:

#### Encrypting Data

Encrypt sensitive data with the `Encrypt` method, providing the data, encryption key, and an initialization vector (IV):

```csharp
string sensitiveData = "This is confidential information.";
string encryptedText = CipherKeyManager.Encrypt(sensitiveData, encryptionKey, encryptionIV);
```

#### Decrypting Data

Decrypt encrypted text using the `Decrypt` method, encryption key, and the same initialization vector (IV):

```csharp
string decryptedText = CipherKeyManager.Decrypt(encryptedText, encryptionKey, encryptionIV);
```

#### Usage Considerations

The CipherKey Manager methods offer an encapsulated and straightforward approach to generating API keys, managing secret encryption keys, and performing data encryption and decryption operations. Incorporate these methods within your application's logic to enhance data security and streamline cryptographic processes.

## Security Best Practices

To ensure the security of your API keys, follow these best practices:

- **Secure Storage**: Store API keys securely, avoiding hardcoding them in your source code or exposing them in public repositories.

- **Key Rotation**: Regularly rotate your API keys to mitigate the risk of unauthorized access.

- **Access Restriction**: Limit the scope of access granted by each API key to only what is necessary. Avoid granting unnecessary permissions.

- **Revocation**: Implement a mechanism to revoke API keys when they are no longer needed or if they have been compromised.

## Contributing

We welcome contributions to CipherKey! If you find bugs, have suggestions for improvements, or want to add new features, feel free to open issues or pull requests in this repository.

## License

CipherKey is released under the [MIT License](LICENSE), which means you can use and modify it freely, as long as you retain the original license notice.

## Contact

If you have any questions or need assistance, you can reach us at diandsonc@gmail.com.

Thank you for choosing CipherKey to secure your API endpoints!
