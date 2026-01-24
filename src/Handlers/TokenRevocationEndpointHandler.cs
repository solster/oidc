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

        // Revoke the token
        await RevokeTokenAsync(request.Token, request.TokenTypeHint, cancellationToken);

        logger.LogInformation("Token revoked for client {ClientId} (hint: {TokenTypeHint})", 
            request.ClientId, request.TokenTypeHint ?? "none");

        // RFC 7009 §2.2: The authorization server responds with HTTP 200
        // Even if the token does not exist or is invalid, respond with 200 to prevent token scanning
        return Results.Ok();
    }

    /// <summary>
    /// Revokes a token by attempting to revoke it from both access and refresh token stores.
    /// Uses token_type_hint to optimize lookup when provided.
    /// Per RFC 7009 §2.1: The server determines whether the hint is correct and may ignore it.
    /// </summary>
    private async Task RevokeTokenAsync(String token, String? tokenTypeHint, CancellationToken cancellationToken)
    {
        try
        {
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
}
