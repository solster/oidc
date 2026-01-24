using Microsoft.Extensions.DependencyInjection.Extensions;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Infrastructure;
using Solster.Authentication.OpenIdConnect.Signing;

namespace Solster.Authentication.OpenIdConnect;

public static class OpenIdConnectServiceCollectionExtensions
{
    /// <summary>
    /// Adds OpenID Connect provider services with the specified issuer.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="issuer">The issuer URL (required).</param>
    /// <param name="configure">Optional action to configure additional options.</param>
    public static IServiceCollection AddOpenIdConnect(this IServiceCollection services, String issuer, Action<OpenIdConnectOptions>? configure = null)
    {
        services.Configure<OpenIdConnectOptions>(options =>
        {
            options.Issuer = issuer;
            configure?.Invoke(options);
        });

        // Register configuration-based signing key store
        // Keys can come from Azure KeyVault (via App Configuration), local config, environment variables, etc.
        services.TryAddSingleton<ISigningKeyStore, ConfigurationSigningKeyStore>();

        // Register JWKS configuration manager as singleton for caching and performance
        // This prevents per-request JWKS fetches and handles network failures gracefully
        services.TryAddSingleton<JwksConfigurationManager>();

        return services;
    }

    /// <summary>
    /// Adds OpenID Connect provider services with configuration action.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure OpenIdConnectOptions.</param>
    public static IServiceCollection AddOpenIdConnect(this IServiceCollection services, Action<OpenIdConnectOptions> configure)
    {
        services.Configure(configure);

        // Register configuration-based signing key store
        // Keys can come from Azure KeyVault (via App Configuration), local config, environment variables, etc.
        services.TryAddSingleton<ISigningKeyStore, ConfigurationSigningKeyStore>();

        // Register JWKS configuration manager as singleton for caching and performance
        // This prevents per-request JWKS fetches and handles network failures gracefully
        services.TryAddSingleton<JwksConfigurationManager>();

        return services;
    }
}

