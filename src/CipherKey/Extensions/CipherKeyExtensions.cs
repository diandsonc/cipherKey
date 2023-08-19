using CipherKey;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Authentication
{
    /// <summary>
    /// Extension methods for adding API key authentication.
    /// </summary>
    public static class CipherKeyExtensions
    {
        /// <summary>
        /// Adds API key authentication and authorization to the application.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddCipherKey(this IServiceCollection services)
            => services.AddCipherKey(CipherKeyDefaults.AuthenticationScheme);

        /// <summary>
        /// Adds API key authentication and authorization to the application.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddCipherKey(this IServiceCollection services, string authenticationScheme)
            => services.AddCipherKey(authenticationScheme, configureOptions: null);

        /// <summary>
        /// Adds API key authentication and authorization to the application.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddCipherKey(
            this IServiceCollection services, Action<CipherKeySchemeOptions> configureOptions)
                => services.AddCipherKey(CipherKeyDefaults.AuthenticationScheme, configureOptions);

        /// <summary>
        /// Adds API key authentication and authorization to the application.
        /// </summary>
        /// <param name="services">The service collection.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddCipherKey(
            this IServiceCollection services, string authenticationScheme,
            Action<CipherKeySchemeOptions>? configureOptions)
        {
            // Add post configure options to the pipeline.
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<CipherKeySchemeOptions>, PostConfigureOptions>());

            // Add API key authentication scheme to the pipeline.
            return services
                .AddAuthentication()
                .AddScheme<CipherKeySchemeOptions, CipherKeyHandler>(authenticationScheme, configureOptions);
        }
    }
}
