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

        /// <summary>
        /// Adds API key authentication and authorization to the application.
        /// </summary>
        /// <typeparam name="TApiKeyProvider">The type of the API key provider.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <param name="configureOptions">The configure options.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddCipherKey<TApiKeyProvider>(
            this IServiceCollection services, string authenticationScheme,
            Action<CipherKeySchemeOptions> configureOptions)
                where TApiKeyProvider : class, IApiKeyProvider
                    => services.AddCipherKey<TApiKeyProvider, CipherKeyHandler>(authenticationScheme, configureOptions);

        private static AuthenticationBuilder AddCipherKey<TApiKeyProvider, TApiKeyHandler>(
            this IServiceCollection services, string authenticationScheme,
            Action<CipherKeySchemeOptions> configureOptions
        )
            where TApiKeyProvider : class, IApiKeyProvider
            where TApiKeyHandler : AuthenticationHandler<CipherKeySchemeOptions>
        {
            // Add implementation of IApiKeyProvider to the dependency container.
            services.AddTransient<IApiKeyProvider, TApiKeyProvider>();
            services.Configure<CipherKeySchemeOptions>(
                authenticationScheme, o => o.ApiKeyProviderType = typeof(TApiKeyProvider));

            // Add post configure options to the pipeline.
            services.TryAddEnumerable(
                    ServiceDescriptor.Singleton<IPostConfigureOptions<CipherKeySchemeOptions>, PostConfigureOptions>());

            // Add API key authentication scheme to the pipeline.
            return services
                .AddAuthentication()
                .AddScheme<CipherKeySchemeOptions, TApiKeyHandler>(authenticationScheme, configureOptions);
        }
    }
}
