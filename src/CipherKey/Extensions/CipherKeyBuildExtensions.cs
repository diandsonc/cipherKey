namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Provides extension methods to add authentication and authorization capabilities to an HTTP application pipeline.
/// </summary>
public static class CipherKeyBuildExtensions
{
    /// <summary>
    /// Adds authentication and authorization middleware to the application pipeline.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The instance of <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UseCipherKey(this IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseAuthorization();

        return app;
    }
}
