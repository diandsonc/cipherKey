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

builder.Services.AddCipherKey<MyProvider>(CipherKeyDefaults.AuthenticationScheme, options =>
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
        OnValidateKey = async context =>
        {
            // Custom validation logic
            if (context.ApiKey == "API_KEY2")
            {
                context.ValidationSucceeded(ownerName: "Lagertha");
            }
            else
            {
                context.ValidationFailed();
            }
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
    [Authorize(AuthenticationSchemes = "Bearer,CipherKey")]
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

- **ApiKey**: The actual API key value that must be along with the request for authentication. It is used to validate the authenticity of the request.

- **Scope**: Defines the level of access or permissions associated with the API key. It specifies what actions or resources the API key holder is authorized to access.

- **ClaimsIssuer**: Specifies the issuer of the claims associated with the authentication token. It helps verify the authenticity of the token and ensures that it was issued by a trusted source.

- **UseFallbackPolicy**: Specifies whether to use the fallback policy for every request by default. When enabled, it challenges authentication for every request. Default value is `true`.

- **AllowOrigins**: Specifies the allowed origins for CORS. It defines which origins are permitted to make API requests, enhancing security and control over cross-origin requests.

- **AllowMethods**: Specifies the allowed HTTP methods for CORS. It defines which HTTP methods are allowed for cross-origin requests.

- **Events**: Provides hooks to attach custom logic or actions during the authentication process. Events can trigger actions such as success, failure.

Integrate these parameters according to your application's requirements to enhance the security and effectiveness of your API authentication process.

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

builder.Services.AddCipherKey<MyProvider>(CipherKeyDefaults.AuthenticationScheme);

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

public class MyProvider : IApiKeyProvider
{
    private List<IApiKey> _cache = new List<IApiKey>
    {
        new ApiKeyAux("myApiKey27", "Lagertha", new string[] { "http://localhost:4200" }),
        new ApiKeyAux("myApiKey11", "Brandon", new string[] { "http://localhost:5081" }),
        new ApiKeyAux("myApiKey88", "Rieka") // Ignore origin
    };

    public Task<IApiKey?> ProvideAsync(string key)
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
            if (context.ApiKey == "API_KEY2")
            {
                context.ValidationSucceeded(ownerName: "Lagertha");
            }
            else
            {
                // If you don't use ValidationFailed in case of failure,
                // the system will attempt to validate the key using your API_KEY and your provider
                context.ValidationFailed();
            }
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
If you implement custom event-based authentication using `OnValidateKey` and do not use `ValidationFailed` in case of a validation failure, the system will automatically attempt to validate the key using the API key configured (`options.ApiKey`) and your custom provider (`MyProvider`), ensuring a seamless authentication process even when custom logic fails. To maintain full control over the validation process, make sure to use `ValidationFailed` appropriately when implementing custom validation logic.

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

The CipherKey Manager provides convenient methods for managing API keys, generating secret encryption keys, and performing data encryption and decryption operations. This section demonstrates how to use the CipherKeyManager methods effectively.

### Generating API Keys

To generate a new API key for your system, use the `GenerateApiKey` method by providing a meaningful name or identifier for your system:

```csharp
string apiKey = CipherKeyManager.GenerateApiKey("mySystem");
```

### Generating Secret Encryption Keys

For secure operations such as data encryption, you can generate a secret encryption key of a specified length using the `GenerateSecretKey` method:

```csharp
string encryptionKey = CipherKeyManager.GenerateSecretKey(32); // Generate a 32-byte encryption key
string encryptionIV = CipherKeyManager.GenerateSecretKey(16); // Generate a 16-byte encryption key
```

### Data Encryption and Decryption

You can use the CipherKey Manager to encrypt and decrypt sensitive data using encryption keys and initialization vectors (IVs). Here's how you can achieve this:

Encrypting Data

Encrypt sensitive data using the `Encrypt` method, providing the data, encryption key, and an initialization vector (IV):

```csharp
string sensitiveData = "This is confidential information.";
string encryptedText = CipherKeyManager.Encrypt(sensitiveData, encryptionKey, encryptionIV);
```

Decrypting Data

To decrypt the encrypted text, use the `Decrypt` method with the encrypted text, encryption key, and the same initialization vector (IV) used for encryption:

```csharp
string decryptedText = CipherKeyManager.Decrypt(encryptedText, encryptionKey, encryptionIV);
```

#### Usage Considerations

The CipherKey Manager provides an encapsulated and straightforward approach to generating API keys, managing secret encryption keys, and performing data encryption and decryption operations. By utilizing these methods, you can enhance the security of your application's sensitive information and streamline your cryptographic processes. Incorporate these methods as needed within your application's logic to achieve secure and efficient data handling.

## Contributing

We welcome contributions to CipherKey! If you find bugs, have suggestions for improvements, or want to add new features, feel free to open issues or pull requests in this repository.

## License

CipherKey is released under the [MIT License](LICENSE), which means you can use and modify it freely, as long as you retain the original license notice.

## Contact

If you have any questions or need assistance, you can reach us at diandsonc@gmail.com.

Thank you for choosing CipherKey to secure your API endpoints!
