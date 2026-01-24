using System.Text.Json;
using Microsoft.Extensions.Options;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Handlers;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect;

public static class OpenIdConnectEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapOpenIdConnect(this IEndpointRouteBuilder endpoints)
    {
        var serviceProvider = endpoints.ServiceProvider;

        var loggerFactory = serviceProvider.GetService<ILoggerFactory>();
        var logger = loggerFactory?.CreateLogger("OpenIdConnect")!;

        var optionsSnapshot = serviceProvider.GetRequiredService<IOptions<OpenIdConnectOptions>>();
        var options = optionsSnapshot.Value;
        var keyStore = serviceProvider.GetRequiredService<ISigningKeyStore>();

        // Map discovery
        endpoints.MapGet("/.well-known/openid-configuration", async context =>
        {
            logger.LogInformation("OpenID discovery requested from {RemoteIp}", context.Connection.RemoteIpAddress?.ToString());

            var origin = GetOrigin(context, options);

            var discovery = new OpenIdConnectDiscoveryDocument
            {
                Issuer = options.Issuer,
                AuthorizationEndpoint = origin.TrimEnd('/') + options.AuthorizationPath,
                TokenEndpoint = origin.TrimEnd('/') + options.TokenPath,
                UserInfoEndpoint = origin.TrimEnd('/') + options.UserInfoPath,
                JwksUri = origin.TrimEnd('/') + options.JwksPath,
                ResponseTypesSupported = options.SupportedResponseTypes,
                SubjectTypesSupported = options.SupportedSubjectTypes,
                IdTokenSigningAlgValuesSupported = options.SupportedIdTokenSigningAlgValues,
                ScopesSupported = options.SupportedScopes,
                TokenEndpointAuthMethodsSupported = options.SupportedTokenEndpointAuthMethods
            };

            context.Response.Headers.CacheControl = $"public, max-age={(Int32)options.DiscoveryCacheDuration.TotalSeconds}";
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.StatusCode = StatusCodes.Status200OK;

            await JsonSerializer.SerializeAsync(context.Response.Body, discovery);
        }).WithDisplayName("OpenIdConnectDiscovery");

        // Map JWKS
        endpoints.MapGet(options.JwksPath, async context =>
        {
            logger.LogInformation("JWKS requested from {RemoteIp}", context.Connection.RemoteIpAddress?.ToString());
            var jwks = keyStore.GetCurrentKeySet();
            context.Response.ContentType = "application/json; charset=utf-8";
            context.Response.StatusCode = StatusCodes.Status200OK;
            await JsonSerializer.SerializeAsync(context.Response.Body, jwks);
        }).WithDisplayName("OpenIdConnectJwks");

        // Map Authorization endpoint
        endpoints.MapGet(options.AuthorizationPath, async (HttpContext context, CancellationToken cancellationToken) =>
        {
            var clientStore = serviceProvider.GetRequiredService<IClientStore>();
            var authenticator = serviceProvider.GetRequiredService<IResourceOwnerAuthenticator>();
            var consentService = serviceProvider.GetRequiredService<IConsentService>();
            var codeStore = serviceProvider.GetRequiredService<IAuthorizationCodeStore>();
            var handlerLogger = loggerFactory?.CreateLogger<AuthorizeEndpointHandler>()!;

            var handler = new AuthorizeEndpointHandler(
                clientStore,
                authenticator,
                consentService,
                codeStore,
                options,
                handlerLogger);

            return await handler.HandleAsync(context, cancellationToken);
        }).WithDisplayName("OpenIdConnectAuthorize");

        // Map Token endpoint - RFC 6749 §3.2
        endpoints.MapPost(options.TokenPath, async (HttpContext context, CancellationToken cancellationToken) =>
        {
            var clientStore = serviceProvider.GetRequiredService<IClientStore>();
            var codeStore = serviceProvider.GetRequiredService<IAuthorizationCodeStore>();
            var claimsProvider = serviceProvider.GetRequiredService<ITokenClaimsProvider>();
            var tokenIssuer = serviceProvider.GetRequiredService<ITokenIssuer>();
            var accessTokenStore = serviceProvider.GetRequiredService<IAccessTokenStore>();
            var handlerLogger = loggerFactory?.CreateLogger<TokenEndpointHandler>()!;

            var handler = new TokenEndpointHandler(
                clientStore,
                codeStore,
                claimsProvider,
                tokenIssuer,
                accessTokenStore,
                options,
                handlerLogger);

            return await handler.HandleAsync(context, cancellationToken);
        }).WithDisplayName("OpenIdConnectToken");

        // Map UserInfo endpoint - OIDC Core §5.3
        endpoints.MapMethods(options.UserInfoPath, new[] { "GET", "POST" }, async (HttpContext context, CancellationToken cancellationToken) =>
        {
            var accessTokenStore = serviceProvider.GetRequiredService<IAccessTokenStore>();
            var claimsProvider = serviceProvider.GetRequiredService<ITokenClaimsProvider>();
            var signingKeyStore = serviceProvider.GetRequiredService<ISigningKeyStore>();
            var handlerLogger = loggerFactory?.CreateLogger<UserInfoEndpointHandler>()!;

            var handler = new UserInfoEndpointHandler(
                accessTokenStore,
                claimsProvider,
                signingKeyStore,
                options,
                handlerLogger);

            return await handler.HandleAsync(context, cancellationToken);
        }).WithDisplayName("OpenIdConnectUserInfo");

        return endpoints;
    }

    private static String GetOrigin(HttpContext context, OpenIdConnectOptions options)
    {
        if (!String.IsNullOrEmpty(options.PublicOrigin))
            return options.PublicOrigin!.TrimEnd('/');

        var req = context.Request;
        var scheme = req.Scheme;
        var host = req.Host.Value;
        return $"{scheme}://{host}";
    }
}