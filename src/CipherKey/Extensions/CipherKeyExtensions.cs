using CipherKey;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;

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

            var configOptions = new CipherKeySchemeOptions();
            configureOptions?.Invoke(configOptions);

            // Add policy
            services.AddPolicy(authenticationScheme, configOptions);

            // Add fallback policy
            services.AddFallbackPolicy(configOptions);

            // Add required scope authorization.
            services.AddScopeAuthorization(configOptions);

            // Add API key authentication scheme to the pipeline.
            return services
                .AddAuthentication(authenticationScheme)
                .AddScheme<CipherKeySchemeOptions, CipherKeyHandler>(authenticationScheme, configureOptions);
        }

        /// <summary>
        /// Adds API key authentication and authorization to the application.
        /// </summary>
        /// <typeparam name="TApiKeyProvider">The type of the API key provider.</typeparam>
        /// <param name="services">The service collection.</param>
        /// <param name="authenticationScheme">The authentication scheme.</param>
        /// <returns>The instance of <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddCipherKey<TApiKeyProvider>(
            this IServiceCollection services, string authenticationScheme)
                where TApiKeyProvider : class, IApiKeyProvider
                    => services
                        .AddCipherKey<TApiKeyProvider, CipherKeyHandler>(authenticationScheme, configureOptions: null);

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
            Action<CipherKeySchemeOptions>? configureOptions
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

            var configOptions = new CipherKeySchemeOptions();
            configureOptions?.Invoke(configOptions);

            // Add policy
            services.AddPolicy(authenticationScheme, configOptions);

            // Add fallback policy
            services.AddFallbackPolicy(configOptions);

            // Add required scope authorization.
            services.AddScopeAuthorization(configOptions);

            // Add API key authentication scheme to the pipeline.
            return services
                .AddAuthentication(authenticationScheme)
                .AddScheme<CipherKeySchemeOptions, TApiKeyHandler>(authenticationScheme, configureOptions);
        }

        private static void AddFallbackPolicy(this IServiceCollection services,
            CipherKeySchemeOptions configureOptions)
        {
            if (!configureOptions.UseFallbackPolicy)
            {
                return;
            }

            services.AddAuthorization(options =>
            {
                options.FallbackPolicy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
            });
        }

        private static void AddScopeAuthorization(this IServiceCollection services,
            CipherKeySchemeOptions configureOptions)
        {
            if (string.IsNullOrEmpty(configureOptions.Scope))
            {
                return;
            }

            services.AddRequiredScopeAuthorization();
        }

        private static void AddPolicy(this IServiceCollection services, string authenticationScheme,
            CipherKeySchemeOptions configureOptions)
        {
            if (configureOptions.AllowOrigins?.Length is null or 0
                && configureOptions.AllowMethods?.Length is null or 0)
            {
                return;
            }

            services.Configure<CipherKeySchemeOptions>(authenticationScheme, o => o.PolicyName = authenticationScheme);

            services.AddCors(options =>
            {
                options.AddPolicy(authenticationScheme, policy =>
                {
                    if (configureOptions.AllowOrigins?.Length > 0)
                    {
                        policy.WithOrigins(configureOptions.AllowOrigins);
                    }
                    else
                    {
                        policy.AllowAnyOrigin();
                    }

                    if (configureOptions.AllowMethods?.Length > 0)
                    {
                        policy.WithMethods(configureOptions.AllowMethods);
                    }
                    else
                    {
                        policy.AllowAnyMethod();
                    }
                });
            });
        }
    }
}
