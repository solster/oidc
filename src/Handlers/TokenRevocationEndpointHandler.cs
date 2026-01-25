using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Handles token revocation requests per RFC 7009.
/// Allows clients to notify the authorization server that a token is no longer needed.
/// </summary>
public class TokenRevocationEndpointHandler(
    IClientStore clientStore,
    IAccessTokenStore accessTokenStore,
    IRefreshTokenStore refreshTokenStore,
    ILogger<TokenRevocationEndpointHandler> logger)
{
    /// <summary>
    /// Handles token revocation endpoint requests.
    /// Per RFC 7009 §2.1: POST-only, requires client authentication, returns 200 OK for all valid requests.
    /// </summary>
    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        logger.LogInformation("Token revocation request from {RemoteIp}", 
            context.Connection.RemoteIpAddress?.ToString());

        // Parse form body (POST method enforced by MapPost routing)
        if (!context.Request.HasFormContentType)
        {
            logger.LogWarning("Token revocation request without form content type from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return Results.BadRequest(new 
            { 
                error = "invalid_request", 
                error_description = "Content-Type must be application/x-www-form-urlencoded" 
            });
        }

        var form = await context.Request.ReadFormAsync(cancellationToken);
        var request = new TokenRevocationRequest
        {
            Token = form["token"].ToString(),
            TokenTypeHint = form["token_type_hint"].ToString(),
            ClientId = form["client_id"].ToString(),
            ClientSecret = form["client_secret"].ToString()
        };

        // Validate required parameters
        if (String.IsNullOrEmpty(request.Token))
        {
            logger.LogWarning("Token revocation request missing token parameter from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return Results.BadRequest(new 
            { 
                error = "invalid_request", 
                error_description = "token parameter is required" 
            });
        }

        if (String.IsNullOrEmpty(request.ClientId) || String.IsNullOrEmpty(request.ClientSecret))
        {
            logger.LogWarning("Token revocation request missing client credentials from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return Results.BadRequest(new 
            { 
                error = "invalid_request", 
                error_description = "client_id and client_secret are required" 
            });
        }

        // RFC 7009 §2.1: Authenticate the client
        var client = await clientStore.ValidateClientAsync(request.ClientId, request.ClientSecret, cancellationToken);
        if (client == null)
        {
            logger.LogWarning("Token revocation with invalid client credentials: {ClientId} from {RemoteIp}", 
                request.ClientId, context.Connection.RemoteIpAddress?.ToString());
            return Results.Json(
                new { error = "invalid_client", error_description = "Client authentication failed" },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        // Revoke the token (with ownership validation)
        await RevokeTokenAsync(request.Token, request.TokenTypeHint, client, cancellationToken);

        logger.LogInformation("Token revoked for client {ClientId} (hint: {TokenTypeHint})", 
            request.ClientId, request.TokenTypeHint ?? "none");

        // RFC 7009 §2.2: The authorization server responds with HTTP 200
        // Even if the token does not exist or is invalid, respond with 200 to prevent token scanning
        return Results.Ok();
    }

    /// <summary>
    /// Revokes a token by attempting to revoke it from both access and refresh token stores.
    /// Uses token_type_hint to optimize lookup when provided.
    /// Per RFC 7009 §2.1: The server validates that the client is authorized to revoke the particular token.
    /// Per RFC 7009 §2.2: Returns success even if token not found or client not authorized (prevents token scanning).
    /// </summary>
    private async Task RevokeTokenAsync(
        String token, 
        String? tokenTypeHint, 
        OAuthClient client,
        CancellationToken cancellationToken)
    {
        try
        {
            // RFC 7009 §2.1: Verify client is authorized to revoke this token
            // Try to find and validate ownership before revoking
            var isAuthorized = await ValidateTokenOwnershipAsync(token, tokenTypeHint, client.ClientId, cancellationToken);
            
            if (!isAuthorized)
            {
                // RFC 7009 §2.2: Silent failure - don't reveal token doesn't exist or isn't owned by client
                logger.LogWarning(
                    "Client {ClientId} attempted to revoke token they don't own or token doesn't exist",
                    client.ClientId);
                return; // Return success (200 OK) without actually revoking
            }

            // Use hint to optimize - try hinted store first
            if (tokenTypeHint == "access_token")
            {
                logger.LogDebug("Token type hint: access_token - attempting access token revocation");
                await accessTokenStore.RevokeTokenAsync(token, cancellationToken);
                // Also try refresh token store in case hint is wrong
                await refreshTokenStore.RevokeTokenAsync(token, "revoked via revocation endpoint", cancellationToken);
            }
            else if (tokenTypeHint == "refresh_token")
            {
                logger.LogDebug("Token type hint: refresh_token - attempting refresh token revocation");
                await refreshTokenStore.RevokeTokenAsync(token, "revoked via revocation endpoint", cancellationToken);
                // Also try access token store in case hint is wrong
                await accessTokenStore.RevokeTokenAsync(token, cancellationToken);
            }
            else
            {
                // No hint or invalid hint - try both stores
                logger.LogDebug("No valid token type hint - attempting revocation in both stores");
                await Task.WhenAll(
                    accessTokenStore.RevokeTokenAsync(token, cancellationToken),
                    refreshTokenStore.RevokeTokenAsync(token, "revoked via revocation endpoint", cancellationToken)
                );
            }
        }
        catch (Exception ex)
        {
            // RFC 7009 §2.2: Even if revocation fails, respond with 200 OK
            // Log the error but don't expose it to the client
            logger.LogWarning(ex, "Error during token revocation (continuing per RFC 7009 §2.2)");
        }
    }

    /// <summary>
    /// Validates that the requesting client owns the token being revoked.
    /// Per RFC 7009 §2.1: Authorization server verifies client is authorized to revoke the token.
    /// </summary>
    private async Task<Boolean> ValidateTokenOwnershipAsync(
        String token,
        String? tokenTypeHint,
        String clientId,
        CancellationToken cancellationToken)
    {
        try
        {
            // Check access token ownership (parse JWT to get jti, then check store)
            if (tokenTypeHint == "access_token" || String.IsNullOrEmpty(tokenTypeHint))
            {
                var tokenId = ExtractJtiFromToken(token);
                if (!String.IsNullOrEmpty(tokenId))
                {
                    var accessToken = await accessTokenStore.GetByTokenIdAsync(tokenId, cancellationToken);
                    if (accessToken != null)
                    {
                        return accessToken.ClientId == clientId;
                    }
                }
            }

            // Check refresh token ownership
            if (tokenTypeHint == "refresh_token" || String.IsNullOrEmpty(tokenTypeHint))
            {
                var refreshToken = await refreshTokenStore.GetByTokenHashAsync(token, cancellationToken);
                if (refreshToken != null)
                {
                    return refreshToken.ClientId == clientId;
                }
            }

            // Token not found - return false (silent failure per RFC 7009 §2.2)
            return false;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Error validating token ownership for client {ClientId}", clientId);
            return false; // Fail closed - deny if we can't verify
        }
    }

    /// <summary>
    /// Extracts the jti (JWT ID) claim from an access token for lookup.
    /// Returns null if token is not a valid JWT.
    /// </summary>
    private String? ExtractJtiFromToken(String token)
    {
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 3)
                return null;

            var payload = parts[1];
            // Add padding if needed
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }

            var jsonBytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
            var json = System.Text.Encoding.UTF8.GetString(jsonBytes);
            
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("jti", out var jtiElement))
            {
                return jtiElement.GetString();
            }
        }
        catch
        {
            // Ignore parsing errors - not a valid JWT
        }

        return null;
    }
}
