using System.IdentityModel.Tokens.Jwt;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Handles token introspection requests per RFC 7662.
/// Allows resource servers to query the status and metadata of access and refresh tokens.
/// </summary>
public class TokenIntrospectionEndpointHandler(
    IClientStore clientStore,
    IAccessTokenStore accessTokenStore,
    IRefreshTokenStore refreshTokenStore,
    OpenIdConnectOptions options,
    ILogger<TokenIntrospectionEndpointHandler> logger)
{
    /// <summary>
    /// Handles token introspection endpoint requests.
    /// Per RFC 7662 §2.1: POST-only, requires client authentication, returns token metadata.
    /// </summary>
    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        logger.LogInformation("Token introspection request from {RemoteIp}", 
            context.Connection.RemoteIpAddress?.ToString());

        // Parse form body (POST method enforced by MapPost routing)
        if (!context.Request.HasFormContentType)
        {
            logger.LogWarning("Token introspection request without form content type from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return Results.BadRequest(new 
            { 
                error = "invalid_request", 
                error_description = "Content-Type must be application/x-www-form-urlencoded" 
            });
        }

        var form = await context.Request.ReadFormAsync(cancellationToken);
        var request = new TokenIntrospectionRequest
        {
            Token = form["token"].ToString(),
            TokenTypeHint = form["token_type_hint"].ToString(),
            ClientId = form["client_id"].ToString(),
            ClientSecret = form["client_secret"].ToString()
        };

        // Validate required parameters
        if (String.IsNullOrEmpty(request.Token))
        {
            logger.LogWarning("Token introspection request missing token parameter from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return Results.BadRequest(new 
            { 
                error = "invalid_request", 
                error_description = "token parameter is required" 
            });
        }

        if (String.IsNullOrEmpty(request.ClientId) || String.IsNullOrEmpty(request.ClientSecret))
        {
            logger.LogWarning("Token introspection request missing client credentials from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return Results.BadRequest(new 
            { 
                error = "invalid_request", 
                error_description = "client_id and client_secret are required" 
            });
        }

        // RFC 7662 §2.1: Authenticate the client
        var client = await clientStore.ValidateClientAsync(request.ClientId, request.ClientSecret, cancellationToken);
        if (client == null)
        {
            logger.LogWarning("Token introspection with invalid client credentials: {ClientId} from {RemoteIp}", 
                request.ClientId, context.Connection.RemoteIpAddress?.ToString());
            return Results.Json(
                new { error = "invalid_client", error_description = "Client authentication failed" },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        // Introspect the token
        var response = await IntrospectTokenAsync(request.Token, request.TokenTypeHint, client.ClientId, cancellationToken);

        logger.LogInformation("Token introspection completed for client {ClientId}, active: {Active}", 
            client.ClientId, response.Active);

        // RFC 7662 §2.2: Always return 200 OK with introspection response
        return Results.Json(response, statusCode: StatusCodes.Status200OK);
    }

    /// <summary>
    /// Introspects a token and returns its metadata.
    /// Per RFC 7662 §2.2: Returns active=false for invalid, expired, revoked, or unauthorized tokens.
    /// </summary>
    private async Task<TokenIntrospectionResponse> IntrospectTokenAsync(
        String tokenValue,
        String? tokenTypeHint,
        String requestingClientId,
        CancellationToken cancellationToken)
    {
        try
        {
            // Normalize hint
            var normalizedHint = NormalizeTokenTypeHint(tokenTypeHint);

            // Try to find and validate the token
            if (normalizedHint == "access_token" || normalizedHint == null)
            {
                var accessTokenResponse = await IntrospectAccessTokenAsync(tokenValue, requestingClientId, cancellationToken);
                if (accessTokenResponse != null)
                    return accessTokenResponse;
            }

            if (normalizedHint == "refresh_token" || normalizedHint == null)
            {
                var refreshTokenResponse = await IntrospectRefreshTokenAsync(tokenValue, requestingClientId, cancellationToken);
                if (refreshTokenResponse != null)
                    return refreshTokenResponse;
            }

            // Token not found or not authorized - return inactive
            return new TokenIntrospectionResponse { Active = false };
        }
        catch (Exception ex)
        {
            // RFC 7662 §2.2: Never expose internal errors - always return inactive
            logger.LogError(ex, "Error during token introspection (returning inactive)");
            return new TokenIntrospectionResponse { Active = false };
        }
    }

    /// <summary>
    /// Introspects an access token (JWT).
    /// </summary>
    private async Task<TokenIntrospectionResponse?> IntrospectAccessTokenAsync(
        String tokenValue,
        String requestingClientId,
        CancellationToken cancellationToken)
    {
        try
        {
            // Parse JWT to extract jti claim
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(tokenValue))
                return null;

            var jwt = handler.ReadJwtToken(tokenValue);
            var jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti)?.Value;
            
            if (String.IsNullOrEmpty(jti))
                return null;

            // Get token reference from store
            var tokenRef = await accessTokenStore.GetByTokenIdAsync(jti, cancellationToken);
            if (tokenRef == null)
                return null;

            // RFC 7662 §2.1: Verify client is authorized to introspect this token
            // Only allow clients to introspect their own tokens
            if (tokenRef.ClientId != requestingClientId)
            {
                logger.LogWarning("Client {RequestingClientId} attempted to introspect token owned by {TokenClientId}",
                    requestingClientId, tokenRef.ClientId);
                return null; // Return null = active: false
            }

            // Check if token is expired
            if (tokenRef.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                return new TokenIntrospectionResponse { Active = false };
            }

            // Check if token is revoked
            if (await accessTokenStore.IsRevokedAsync(jti, cancellationToken))
            {
                return new TokenIntrospectionResponse { Active = false };
            }

            // Extract claims from JWT
            var sub = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            var scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;
            var aud = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Aud)?.Value;
            var iss = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Iss)?.Value;

            // Build active response with token metadata
            return new TokenIntrospectionResponse
            {
                Active = true,
                Scope = scope,
                ClientId = tokenRef.ClientId,
                Username = tokenRef.UserId, // human-readable identifier
                TokenType = "Bearer",
                Exp = tokenRef.ExpiresAt.ToUnixTimeSeconds(),
                Iat = tokenRef.CreatedAt.ToUnixTimeSeconds(),
                Sub = sub ?? tokenRef.UserId,
                Aud = aud,
                Iss = iss,
                Jti = jti
            };
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to introspect as access token");
            return null;
        }
    }

    /// <summary>
    /// Introspects a refresh token (opaque token).
    /// </summary>
    private async Task<TokenIntrospectionResponse?> IntrospectRefreshTokenAsync(
        String tokenValue,
        String requestingClientId,
        CancellationToken cancellationToken)
    {
        try
        {
            // Get refresh token from store
            var refreshToken = await refreshTokenStore.GetByTokenHashAsync(tokenValue, cancellationToken);
            if (refreshToken == null)
                return null;

            // RFC 7662 §2.1: Verify client is authorized to introspect this token
            if (refreshToken.ClientId != requestingClientId)
            {
                logger.LogWarning("Client {RequestingClientId} attempted to introspect refresh token owned by {TokenClientId}",
                    requestingClientId, refreshToken.ClientId);
                return null; // Return null = active: false
            }

            // Check if token is expired
            if (refreshToken.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                return new TokenIntrospectionResponse { Active = false };
            }

            // Check if token is revoked
            if (refreshToken.RevokedAt.HasValue)
            {
                return new TokenIntrospectionResponse { Active = false };
            }

            // Check if token has been consumed (used for rotation)
            if (refreshToken.ConsumedAt.HasValue)
            {
                return new TokenIntrospectionResponse { Active = false };
            }

            // Build active response with token metadata
            return new TokenIntrospectionResponse
            {
                Active = true,
                Scope = String.Join(" ", refreshToken.Scopes),
                ClientId = refreshToken.ClientId,
                Username = refreshToken.UserId,
                TokenType = "refresh_token",
                Exp = refreshToken.ExpiresAt.ToUnixTimeSeconds(),
                Iat = refreshToken.CreatedAt.ToUnixTimeSeconds(),
                Sub = refreshToken.UserId,
                Iss = options.Issuer
            };
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to introspect as refresh token");
            return null;
        }
    }

    /// <summary>
    /// Normalizes token type hint to valid values.
    /// RFC 7662 §2.1: Invalid hints should be ignored.
    /// </summary>
    private String? NormalizeTokenTypeHint(String? hint)
    {
        if (String.IsNullOrWhiteSpace(hint))
            return null;

        return hint switch
        {
            "access_token" => "access_token",
            "refresh_token" => "refresh_token",
            _ => null // Invalid hints treated as no hint
        };
    }
}
