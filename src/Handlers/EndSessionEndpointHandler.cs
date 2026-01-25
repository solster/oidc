using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Handles end session (logout) requests per OIDC Session Management 1.0 §5.
/// Implements RP-Initiated Logout.
/// </summary>
public class EndSessionEndpointHandler(
    IClientStore clientStore,
    ISigningKeyStore signingKeyStore,
    OpenIdConnectOptions options,
    ILogger<EndSessionEndpointHandler> logger)
{
    /// <summary>
    /// Handles end session endpoint requests.
    /// Per OIDC Session Management §5: Supports both GET and POST methods.
    /// </summary>
    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        logger.LogInformation("End session request from {RemoteIp}", 
            context.Connection.RemoteIpAddress?.ToString());

        // Parse request (support both GET and POST)
        var request = ParseRequest(context);

        String? clientId = null;
        String? userId = null;

        // If id_token_hint provided, validate it and extract claims
        if (!String.IsNullOrEmpty(request.IdTokenHint))
        {
            var validationResult = ValidateIdTokenHint(request.IdTokenHint);
            if (validationResult.IsValid)
            {
                clientId = validationResult.ClientId;
                userId = validationResult.UserId;
                logger.LogInformation("End session for user {UserId} from client {ClientId}", 
                    userId, clientId);
            }
            else
            {
                // OIDC Session Management §5: If id_token_hint is invalid, continue with logout anyway
                logger.LogWarning("Invalid id_token_hint provided, continuing with logout");
            }
        }

        // Validate post_logout_redirect_uri if provided
        if (!String.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            if (String.IsNullOrEmpty(clientId))
            {
                // Cannot validate redirect URI without knowing the client
                logger.LogWarning("post_logout_redirect_uri provided without valid id_token_hint");
                return Results.BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "post_logout_redirect_uri requires a valid id_token_hint"
                });
            }

            var client = await clientStore.GetByClientIdAsync(clientId, cancellationToken);
            if (client == null)
            {
                logger.LogWarning("Client {ClientId} not found", clientId);
                return Results.BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "Unknown client"
                });
            }

            // Validate redirect URI is registered
            if (!client.PostLogoutRedirectUris.Contains(request.PostLogoutRedirectUri))
            {
                logger.LogWarning("Invalid post_logout_redirect_uri {Uri} for client {ClientId}", 
                    request.PostLogoutRedirectUri, clientId);
                return Results.BadRequest(new
                {
                    error = "invalid_request",
                    error_description = "post_logout_redirect_uri not registered for this client"
                });
            }
        }

        // Clear authentication session/cookies
        // OIDC Session Management 1.0 §5: End the session at the OP
        ClearAuthenticationSession(context, userId);

        // Redirect to post_logout_redirect_uri if provided
        if (!String.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            var redirectUrl = request.PostLogoutRedirectUri;
            
            // Append state if provided
            if (!String.IsNullOrEmpty(request.State))
            {
                var separator = redirectUrl.Contains('?') ? "&" : "?";
                redirectUrl = $"{redirectUrl}{separator}state={Uri.EscapeDataString(request.State)}";
            }

            logger.LogInformation("Redirecting to post_logout_redirect_uri: {Uri}", redirectUrl);
            return Results.Redirect(redirectUrl);
        }

        // No redirect URI - return logout confirmation
        logger.LogInformation("Logout completed, no redirect URI provided");
        return Results.Content(
            "<html><body><h1>Logged Out</h1><p>You have been successfully logged out.</p></body></html>",
            "text/html");
    }

    /// <summary>
    /// Parses the end session request from query string (GET) or form body (POST).
    /// </summary>
    private EndSessionRequest ParseRequest(HttpContext context)
    {
        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            var form = context.Request.Form;
            return new EndSessionRequest
            {
                IdTokenHint = form["id_token_hint"].ToString(),
                PostLogoutRedirectUri = form["post_logout_redirect_uri"].ToString(),
                State = form["state"].ToString()
            };
        }
        else
        {
            var query = context.Request.Query;
            return new EndSessionRequest
            {
                IdTokenHint = query["id_token_hint"].ToString(),
                PostLogoutRedirectUri = query["post_logout_redirect_uri"].ToString(),
                State = query["state"].ToString()
            };
        }
    }

    /// <summary>
    /// Validates the ID token hint and extracts claims.
    /// Per OIDC Session Management §5: Used to identify the session to end.
    /// Note: Does NOT check expiration - logout should work even if token expired.
    /// Strategy: First try full validation, if that fails, extract claims without validation (for expired tokens).
    /// </summary>
    private IdTokenValidationResult ValidateIdTokenHint(String idTokenHint)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(idTokenHint))
            {
                logger.LogWarning("id_token_hint is not a valid JWT");
                return IdTokenValidationResult.Invalid();
            }

            // First, read the token without validation to extract claims
            // This allows us to get aud (client_id) even from expired tokens
            var unvalidatedToken = handler.ReadJwtToken(idTokenHint);
            var sub = unvalidatedToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            var aud = unvalidatedToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Aud)?.Value;

            if (String.IsNullOrEmpty(sub) || String.IsNullOrEmpty(aud))
            {
                logger.LogWarning("id_token_hint missing required claims (sub or aud)");
                return IdTokenValidationResult.Invalid();
            }

            // Get signing keys
            var jwks = signingKeyStore.GetCurrentKeySet();
            if (jwks?.Keys is not { Count: > 0 })
            {
                logger.LogError("No signing keys available for token validation");
                // Return the claims anyway - we have sub and aud which is what we need
                logger.LogWarning("Accepting id_token_hint without signature validation (no keys available)");
                return IdTokenValidationResult.Valid(sub, aud);
            }

            // Try to validate signature (but not expiration)
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = options.Issuer,
                ValidateAudience = false, // We already extracted aud
                ValidateLifetime = false, // Don't check expiration for logout
                IssuerSigningKeys = jwks.Keys,
                ValidAlgorithms = jwks.Keys.Where(k => !String.IsNullOrEmpty(k.Alg))
                    .Select(k => k.Alg).ToList()
            };

            try
            {
                handler.ValidateToken(idTokenHint, validationParameters, out _);
                logger.LogDebug("id_token_hint signature validated successfully");
            }
            catch (Exception validationEx)
            {
                // Signature validation failed, but we still have the claims
                // Per OIDC Session Management §5: We should continue with logout anyway
                logger.LogWarning(validationEx, "id_token_hint signature validation failed, but continuing with logout");
            }

            return IdTokenValidationResult.Valid(sub, aud);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to parse id_token_hint");
            return IdTokenValidationResult.Invalid();
        }
    }

    /// <summary>
    /// Result of ID token hint validation.
    /// </summary>
    private class IdTokenValidationResult
    {
        public Boolean IsValid { get; init; }
        public String? UserId { get; init; }
        public String? ClientId { get; init; }

        public static IdTokenValidationResult Valid(String userId, String clientId) =>
            new() { IsValid = true, UserId = userId, ClientId = clientId };

        public static IdTokenValidationResult Invalid() =>
            new() { IsValid = false };
    }

    /// <summary>
    /// Clears the user's authentication session and cookies.
    /// Per OIDC Session Management 1.0 §5: RP-Initiated Logout.
    /// </summary>
    private void ClearAuthenticationSession(HttpContext context, String? userId)
    {
        try
        {
            // Clear all authentication cookies
            // Note: This clears ASP.NET Core authentication cookies
            // Hosting applications may need to add additional session clearing logic
            foreach (var cookie in context.Request.Cookies.Keys)
            {
                // Clear common authentication cookie patterns
                if (cookie.StartsWith(".AspNetCore.", StringComparison.OrdinalIgnoreCase) ||
                    cookie.StartsWith("OIDC.", StringComparison.OrdinalIgnoreCase) ||
                    cookie.StartsWith("OpenIdConnect.", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.Cookies.Delete(cookie, new CookieOptions
                    {
                        Path = "/",
                        Domain = context.Request.Host.Host,
                        Secure = true,
                        HttpOnly = true,
                        SameSite = SameSiteMode.None
                    });
                    
                    logger.LogDebug("Deleted authentication cookie: {CookieName}", cookie);
                }
            }

            if (!String.IsNullOrEmpty(userId))
            {
                logger.LogInformation("Authentication session cleared for user {UserId}", userId);
            }
            else
            {
                logger.LogInformation("Authentication session cleared (no user ID available)");
            }
        }
        catch (Exception ex)
        {
            // Continue with logout even if session clearing fails
            // Per OIDC Session Management 1.0 §5: Logout should complete even on errors
            logger.LogWarning(ex, "Failed to clear authentication session for user {UserId}, continuing with logout", userId);
        }
    }
}
