using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Solster.Authentication.OpenIdConnect.Abstractions;

namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Handles OIDC UserInfo endpoint requests per OIDC Core §5.3.
/// Returns claims about the authenticated end-user.
/// </summary>
public class UserInfoEndpointHandler(
    IAccessTokenStore accessTokenStore,
    ITokenClaimsProvider claimsProvider,
    ISigningKeyStore signingKeyStore,
    OpenIdConnectOptions options,
    ILogger<UserInfoEndpointHandler> logger)
{
    /// <summary>
    /// Handles UserInfo endpoint requests.
    /// Supports both GET and POST methods per OIDC Core §5.3.1.
    /// </summary>
    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        logger.LogInformation("UserInfo request from {RemoteIp}", context.Connection.RemoteIpAddress?.ToString());

        // Extract access token per RFC 6750 (priority: Header > Body > Query)
        String? accessToken = null;
        String tokenSource = "none";

        // RFC 6750 §2.1: Authorization header (RECOMMENDED)
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!String.IsNullOrEmpty(authHeader))
        {
            if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning("UserInfo request with invalid Authorization scheme from {RemoteIp}",
                    context.Connection.RemoteIpAddress?.ToString());
                return UnauthorizedResponse("Authorization header must use Bearer scheme");
            }
            
            accessToken = authHeader.Substring("Bearer ".Length).Trim();
            tokenSource = "header";
        }
        // RFC 6750 §2.2: Form-encoded body parameter (POST only)
        else if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(cancellationToken);
            accessToken = form["access_token"].ToString();
            tokenSource = "body";
        }
        // RFC 6750 §2.3: URI query parameter (NOT RECOMMENDED - less secure)
        else if (HttpMethods.IsGet(context.Request.Method))
        {
            accessToken = context.Request.Query["access_token"].ToString();
            if (!String.IsNullOrEmpty(accessToken))
            {
                tokenSource = "query";
                logger.LogWarning("Access token provided in query string (insecure). Consider using Authorization header. RemoteIp: {RemoteIp}",
                    context.Connection.RemoteIpAddress?.ToString());
            }
        }
        
        if (String.IsNullOrEmpty(accessToken))
        {
            // Provide specific error message based on whether Authorization header was attempted
            var errorMessage = String.IsNullOrEmpty(authHeader) 
                ? "Missing Authorization header" 
                : "Access token is required";
            
            logger.LogWarning("UserInfo request missing access token from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return UnauthorizedResponse(errorMessage);
        }

        logger.LogDebug("Access token extracted from {TokenSource}", tokenSource);

        // Validate JWT token (signature, issuer, audience, lifetime)
        var validationResult = ValidateAccessToken(accessToken);
        
        if (!validationResult.IsValid || validationResult.Principal == null)
        {
            logger.LogWarning("UserInfo request with invalid or expired access token from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return validationResult.ErrorResult ?? UnauthorizedResponse("Invalid or expired access token");
        }

        var principal = validationResult.Principal;
        var tokenId = validationResult.TokenId;

        // Validate token ID (jti) is present - required for revocation check
        if (String.IsNullOrEmpty(tokenId))
        {
            logger.LogWarning("Access token missing 'jti' claim, cannot verify revocation status");
            return UnauthorizedResponse("Invalid access token: missing token identifier");
        }

        // Check if token has been revoked
        var isRevoked = await accessTokenStore.IsRevokedAsync(tokenId, cancellationToken);
        if (isRevoked)
        {
            logger.LogWarning("Revoked access token presented to UserInfo endpoint. TokenId: {TokenId}, RemoteIp: {RemoteIp}", 
                tokenId, context.Connection.RemoteIpAddress?.ToString());
            return UnauthorizedResponse("Access token has been revoked");
        }
        
        logger.LogDebug("Token revocation check passed for TokenId: {TokenId}", tokenId);

        // Extract subject (user ID) and scopes from token
        var userId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        
        if (String.IsNullOrEmpty(userId))
        {
            logger.LogWarning("Access token missing 'sub' claim from {RemoteIp}", 
                context.Connection.RemoteIpAddress?.ToString());
            return UnauthorizedResponse("Invalid access token: missing subject");
        }

        var scopeClaim = principal.FindFirst("scope")?.Value ?? "";
        var scopes = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        logger.LogDebug("Retrieving UserInfo for user {UserId} with scopes: {Scopes}", userId, String.Join(", ", scopes));

        // Get user claims from provider
        var userClaims = await claimsProvider.GetUserInfoClaimsAsync(userId, scopes, cancellationToken);

        // Build response as JSON object
        var userInfo = new Dictionary<String, Object>();
        
        // Always include 'sub' claim (OIDC Core §5.3.2)
        userInfo["sub"] = userId;

        // Add additional claims, grouping by claim type to handle duplicates
        var claimGroups = userClaims
            .Where(c => c.Type != "sub" && c.Type != JwtRegisteredClaimNames.Sub)
            .GroupBy(c => c.Type);

        foreach (var group in claimGroups)
        {
            var values = group.Select(c => c.Value).ToArray();
            // Single value: store as string; Multiple values: store as array
            userInfo[group.Key] = values.Length == 1 ? values[0] : values;
        }

        logger.LogInformation("UserInfo successfully retrieved for user {UserId}", userId);

        // Return JSON response (OIDC Core §5.3.2) with security headers
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.StatusCode = StatusCodes.Status200OK;
        
        // Security headers: prevent caching of sensitive user information (RFC 6750 §3.1)
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        
        return Results.Json(userInfo);
    }

    /// <summary>
    /// Validates an access token JWT and returns the principal.
    /// Implements RFC 6750 and RFC 8725 token validation with comprehensive error handling.
    /// Note: Synchronous by design - token validation is CPU-bound cryptographic operation.
    /// </summary>
    private TokenValidationResult ValidateAccessToken(String token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler
            {
                // Disable claim type mapping to preserve OIDC standard claim names (sub, jti, scope)
                // instead of mapping to .NET Framework claim types (nameidentifier, etc.)
                MapInboundClaims = false
            };
            
            // Get current signing keys from local key store
            var jwks = signingKeyStore.GetCurrentKeySet();
            
            if (jwks?.Keys == null || jwks.Keys.Count == 0)
            {
                logger.LogError("No signing keys available for token validation");
                return TokenValidationResult.ServiceUnavailable("Token validation service misconfigured");
            }

            // Extract supported algorithms from signing keys
            var supportedAlgorithms = new HashSet<String>();
            foreach (var key in jwks.Keys)
            {
                if (!String.IsNullOrEmpty(key.Alg))
                {
                    supportedAlgorithms.Add(key.Alg);
                }
            }
            
            // FAIL CLOSED: If no algorithms specified, reject tokens (security over availability)
            if (supportedAlgorithms.Count == 0)
            {
                logger.LogError("JWKS contains no algorithm information - cannot validate tokens");
                return TokenValidationResult.ServiceUnavailable("Token validation service misconfigured");
            }

            logger.LogDebug("Token validation using algorithms: {Algorithms}", String.Join(", ", supportedAlgorithms));

            var validationParameters = new TokenValidationParameters
            {
                // Issuer validation - REQUIRED for security (RFC 8725 §3.1)
                ValidateIssuer = true,
                ValidIssuer = options.Issuer,
                
                // Audience validation - REQUIRED to prevent token misuse across services
                ValidateAudience = options.ValidateUserInfoAudience,
                ValidAudience = options.UserInfoAudience, // Always set, validation flag controls checking
                
                // Lifetime validation - REQUIRED (RFC 8725 §3.4)
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5), // Allow 5 minutes clock skew
                
                // Signature validation - REQUIRED (RFC 8725 §3.2)
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = jwks.Keys,
                
                // Algorithm validation - only accept algorithms from our signing keys (RFC 8725 §3.1)
                ValidAlgorithms = supportedAlgorithms
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);
            
            // Verify it's a JWT (not some other token format)
            if (validatedToken is not JwtSecurityToken jwtToken)
            {
                logger.LogWarning("Token is not a JWT");
                return TokenValidationResult.Invalid();
            }
            
            // Verify signing algorithm to prevent 'none' algorithm attacks (RFC 8725 §3.1)
            if (jwtToken.Header.Alg == SecurityAlgorithms.None || 
                String.IsNullOrEmpty(jwtToken.Header.Alg))
            {
                logger.LogWarning("Token uses insecure 'none' algorithm");
                return TokenValidationResult.Invalid();
            }
            
            // Extract token ID (jti) for revocation check
            var tokenId = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            
            logger.LogDebug("Access token validated successfully for issuer {Issuer}", jwtToken.Issuer);
            return TokenValidationResult.Success(principal, tokenId);
        }
        catch (SecurityTokenExpiredException ex)
        {
            // Log expired tokens separately as they're common and business-relevant
            logger.LogWarning("Access token expired: {Message}", ex.Message);
            return TokenValidationResult.Invalid();
        }
        catch (SecurityTokenException ex)
        {
            // Covers: InvalidSignatureException, InvalidIssuerException, InvalidAudienceException, etc.
            logger.LogWarning("Token validation failed ({ExceptionType}): {Message}", 
                ex.GetType().Name, ex.Message);
            return TokenValidationResult.Invalid();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error during token validation");
            return TokenValidationResult.Invalid();
        }
    }

    /// <summary>
    /// Result of token validation with optional error response.
    /// </summary>
    private record TokenValidationResult(
        Boolean IsValid,
        ClaimsPrincipal? Principal,
        String? TokenId,
        IResult? ErrorResult)
    {
        public static TokenValidationResult Success(ClaimsPrincipal principal, String? tokenId) =>
            new(true, principal, tokenId, null);

        public static TokenValidationResult Invalid() =>
            new(false, null, null, null);

        public static TokenValidationResult ServiceUnavailable(String message) =>
            new(false, null, null, Results.Json(
                new { error = "temporarily_unavailable", error_description = message },
                statusCode: StatusCodes.Status503ServiceUnavailable,
                contentType: "application/json; charset=utf-8"));
    }

    /// <summary>
    /// Returns a 401 Unauthorized response with RFC 6750 compliant WWW-Authenticate header.
    /// Per RFC 6750 §3.1 (OAuth 2.0 Bearer Token Usage).
    /// </summary>
    private static IResult UnauthorizedResponse(String errorDescription)
    {
        return new BearerUnauthorizedResult(errorDescription);
    }
}
