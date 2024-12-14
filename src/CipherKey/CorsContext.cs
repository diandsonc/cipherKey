using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace CipherKey;

/// <summary>
/// Context used for validating CORS.
/// </summary>
public class CorsContext : ResultContext<CipherKeySchemeOptions>
{
    private readonly ICorsService _corsService;
    private readonly ICorsPolicyProvider _corsPolicyProvider;

    /// <summary>
    /// Initializes a new instance of the <see cref="CorsContext"/> class.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="scheme">The authentication scheme.</param>
    /// <param name="options">The authentication options.</param>
    /// <param name="corsService">The CORS service.</param>
    /// <param name="corsPolicyProvider">The CORS policy provider.</param>
    public CorsContext(HttpContext context, AuthenticationScheme scheme, CipherKeySchemeOptions options,
        ICorsService corsService, ICorsPolicyProvider corsPolicyProvider)
        : base(context, scheme, options)
    {
        _corsService = corsService ?? throw new ArgumentNullException(nameof(corsService));
        _corsPolicyProvider = corsPolicyProvider ?? throw new ArgumentNullException(nameof(corsPolicyProvider));
    }

    /// <summary>
    /// Validates the CORS policy for the request.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task ValidateCorsAsync()
    {
        if (string.IsNullOrEmpty(Options.PolicyName))
        {
            return;
        }

        var policy = await _corsPolicyProvider
            .GetPolicyAsync(Request.HttpContext, Options.PolicyName)
            .ConfigureAwait(false);

        if (policy is null)
        {
            throw new InvalidOperationException
                ($"Error getting policy {nameof(CipherKeySchemeOptions.PolicyName)}.");
        }

        var corsResult = _corsService.EvaluatePolicy(Request.HttpContext, policy);

        if (corsResult.IsOriginAllowed is false)
        {
            Fail($"Origin {Request.Headers.Origin} not allowed.");
        }

        if (!policy.AllowAnyMethod && !policy.Methods.Any(x => x == Request.Method))
        {
            Fail($"Method {Request.Method} not allowed.");
        }
    }
}
