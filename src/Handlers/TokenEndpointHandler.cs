using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Handles OAuth2/OIDC token requests with authorization code grant support.
/// Implements RFC 6749 §4.1.3 (Token Request) and RFC 7636 (PKCE).
/// </summary>
public class TokenEndpointHandler(
    IClientStore clientStore,
    IAuthorizationCodeStore codeStore,
    ITokenClaimsProvider claimsProvider,
    ITokenIssuer tokenIssuer,
    IAccessTokenStore accessTokenStore,
    OpenIdConnectOptions options,
    ILogger<TokenEndpointHandler> logger)
{
    /// <summary>
    /// Handles token endpoint requests.
    /// </summary>
    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        logger.LogInformation("Token request from {RemoteIp}", context.Connection.RemoteIpAddress?.ToString());

        // RFC 6749 §3.2: Token endpoint MUST only accept POST
        if (!HttpMethods.IsPost(context.Request.Method))
        {
            logger.LogWarning("Invalid HTTP method: {Method}", context.Request.Method);
            return ErrorResponse("invalid_request", "Token endpoint only accepts POST requests", StatusCodes.Status405MethodNotAllowed);
        }

        // RFC 6749 §3.2: Token endpoint MUST accept application/x-www-form-urlencoded
        if (!context.Request.HasFormContentType)
        {
            logger.LogWarning("Invalid content type: {ContentType}", context.Request.ContentType);
            return ErrorResponse("invalid_request", "Content-Type must be application/x-www-form-urlencoded");
        }

        var form = await context.Request.ReadFormAsync(cancellationToken);

        // Extract grant_type
        var grantType = form["grant_type"].ToString();
        if (String.IsNullOrEmpty(grantType))
        {
            logger.LogWarning("Missing grant_type");
            return ErrorResponse("invalid_request", "grant_type is required");
        }

        // RFC 6749 §4.1.3: Only support authorization_code grant for Phase 3
        if (grantType != "authorization_code")
        {
            logger.LogWarning("Unsupported grant_type: {GrantType}", grantType);
            return ErrorResponse("unsupported_grant_type", $"Grant type '{grantType}' is not supported");
        }

        // Extract parameters
        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var codeVerifier = form["code_verifier"].ToString();
        var clientIdForm = form["client_id"].ToString();
        var clientSecretForm = form["client_secret"].ToString();

        // RFC 6749 §4.1.3: code and redirect_uri are REQUIRED
        if (String.IsNullOrEmpty(code))
        {
            logger.LogWarning("Missing code");
            return ErrorResponse("invalid_request", "code is required");
        }

        if (String.IsNullOrEmpty(redirectUri))
        {
            logger.LogWarning("Missing redirect_uri");
            return ErrorResponse("invalid_request", "redirect_uri is required");
        }

        // Client Authentication - RFC 6749 §2.3
        var (client, authError) = await AuthenticateClientAsync(context, clientIdForm, clientSecretForm, cancellationToken);
        
        if (client == null)
        {
            logger.LogWarning("Client authentication failed");
            return authError!;
        }

        logger.LogInformation("Client {ClientId} authenticated successfully", client.ClientId);

        // Step 1: Retrieve code without consuming (allows specific error messages before consumption)
        var authCode = await codeStore.GetCodeAsync(code, cancellationToken);
        
        if (authCode == null)
        {
            logger.LogWarning("Authorization code not found");
            return ErrorResponse("invalid_grant", "Authorization code is invalid");
        }

        // Step 2: Check expiry BEFORE consuming (RFC 6749 §4.1.2 - expired codes should not be consumed)
        if (authCode.ExpiresAt < DateTimeOffset.UtcNow)
        {
            logger.LogWarning("Authorization code expired for client {ClientId}", client.ClientId);
            return ErrorResponse("invalid_grant", "Authorization code has expired");
        }

        // Step 3: Check if already consumed (RFC 6749 §10.5 - code reuse attack)
        if (authCode.IsConsumed)
        {
            logger.LogWarning("Authorization code reuse detected for code {Code} - revoking all associated tokens", code);
            
            // RFC 6749 §10.5: MUST revoke all tokens previously issued based on that authorization code
            var revokedCount = await accessTokenStore.RevokeTokensByAuthorizationCodeAsync(code, cancellationToken);
            logger.LogWarning("Revoked {Count} token(s) due to authorization code reuse", revokedCount);
            
            return ErrorResponse("invalid_grant", "Authorization code has already been used");
        }

        // Step 4: Validate client_id matches BEFORE consuming
        if (authCode.ClientId != client.ClientId)
        {
            logger.LogWarning("Client ID mismatch. Code issued to {CodeClientId}, presented by {PresentedClientId}", 
                authCode.ClientId, client.ClientId);
            return ErrorResponse("invalid_grant", "Authorization code was not issued to this client");
        }

        // Step 5: Validate redirect_uri BEFORE consuming (RFC 6749 §4.1.3)
        if (!authCode.RedirectUri.Equals(redirectUri, StringComparison.Ordinal))
        {
            logger.LogWarning("Redirect URI mismatch for client {ClientId}. Expected: {Expected}, Got: {Got}", 
                client.ClientId, authCode.RedirectUri, redirectUri);
            return ErrorResponse("invalid_grant", "redirect_uri does not match the one from authorization request");
        }

        // PKCE validation BEFORE consuming - RFC 7636 §4.6
        if (options.RequirePkce || !String.IsNullOrEmpty(authCode.CodeChallenge))
        {
            if (String.IsNullOrEmpty(codeVerifier))
            {
                logger.LogWarning("Missing code_verifier for client {ClientId}", client.ClientId);
                return ErrorResponse("invalid_grant", "code_verifier is required");
            }

            // RFC 7636 §4.1: code_verifier must be 43-128 characters
            if (codeVerifier.Length < 43 || codeVerifier.Length > 128)
            {
                logger.LogWarning("Invalid code_verifier length for client {ClientId}: {Length}", client.ClientId, codeVerifier.Length);
                return ErrorResponse("invalid_grant", "code_verifier must be between 43 and 128 characters");
            }

            // Validate PKCE challenge
            if (!AuthorizeEndpointHandler.ValidatePkceChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod))
            {
                logger.LogWarning("PKCE validation failed for client {ClientId}", client.ClientId);
                return ErrorResponse("invalid_grant", "code_verifier does not match code_challenge");
            }

            logger.LogDebug("PKCE validation successful for client {ClientId}", client.ClientId);
        }

        // Step 6: All validations passed - now atomically consume the code
        var consumedCode = await codeStore.ConsumeCodeAsync(code, cancellationToken);
        
        if (consumedCode == null)
        {
            // Race condition: Check if code was consumed during validation (RFC 6749 §10.5 - code reuse)
            var recheck = await codeStore.GetCodeAsync(code, cancellationToken);
            
            if (recheck?.IsConsumed == true)
            {
                // Code was consumed between get and consume - this is a reuse attempt
                logger.LogWarning("Authorization code reuse detected in race condition for client {ClientId} - revoking tokens", client.ClientId);
                var revokedCount = await accessTokenStore.RevokeTokensByAuthorizationCodeAsync(code, cancellationToken);
                logger.LogWarning("Revoked {Count} token(s) due to authorization code reuse in race condition", revokedCount);
                return ErrorResponse("invalid_grant", "Authorization code has already been used");
            }
            
            // Code expired or was invalidated during processing (not a reuse)
            logger.LogWarning("Authorization code no longer valid (expired during processing) for client {ClientId}", client.ClientId);
            return ErrorResponse("invalid_grant", "Authorization code is no longer valid");
        }

        logger.LogInformation("Authorization code validated and consumed for user {UserId} and client {ClientId}", 
            consumedCode.UserId, client.ClientId);

        // Generate tokens
        var scopes = consumedCode.RequestedScopes;
        var authTime = consumedCode.CreatedAt;

        // Get claims from provider
        var idTokenClaims = await claimsProvider.GetIdTokenClaimsAsync(consumedCode.UserId, client.ClientId, scopes, cancellationToken);
        var accessTokenClaims = await claimsProvider.GetAccessTokenClaimsAsync(consumedCode.UserId, client.ClientId, scopes, cancellationToken);

        // Generate ID token with nonce (OIDC Core §3.1.3.3)
        var idToken = await tokenIssuer.IssueIdTokenAsync(
            consumedCode.UserId,
            client.ClientId,
            consumedCode.Nonce,
            authTime,
            idTokenClaims,
            options.IdTokenLifetime,
            cancellationToken);

        // Generate access token (RFC 6749 §5.1)
        var accessToken = await tokenIssuer.IssueAccessTokenAsync(
            consumedCode.UserId,
            client.ClientId,
            scopes,
            accessTokenClaims,
            options.AccessTokenLifetime,
            cancellationToken);

        // Extract jti from access token for revocation tracking
        var tokenId = ExtractJtiFromJwt(accessToken);
        
        // Save access token reference for revocation (RFC 6749 §10.5 - track authorization code for revocation)
        await accessTokenStore.SaveTokenAsync(new AccessTokenReference
        {
            TokenId = tokenId,
            UserId = consumedCode.UserId,
            ClientId = client.ClientId,
            AuthorizationCode = code,
            ExpiresAt = DateTimeOffset.UtcNow.Add(options.AccessTokenLifetime),
            CreatedAt = DateTimeOffset.UtcNow
        }, cancellationToken);

        logger.LogInformation("Tokens issued for user {UserId} and client {ClientId}", consumedCode.UserId, client.ClientId);

        // Build token response - RFC 6749 §5.1, OIDC Core §3.1.3.3
        var response = new TokenResponse
        {
            IdToken = idToken,
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = (Int32)options.AccessTokenLifetime.TotalSeconds,
            Scope = String.Join(" ", scopes)
        };

        return Results.Json(response, statusCode: StatusCodes.Status200OK);
    }

    /// <summary>
    /// Authenticates the client using one of three methods per RFC 6749 §2.3:
    /// - client_secret_basic (Authorization header with Basic auth)
    /// - client_secret_post (client_id and client_secret in form body)
    /// - none (public clients with only client_id)
    /// </summary>
    private async Task<(OAuthClient? client, IResult? error)> AuthenticateClientAsync(
        HttpContext context,
        String? clientIdForm,
        String? clientSecretForm,
        CancellationToken cancellationToken)
    {
        String? clientId = null;
        String? clientSecret = null;

        // RFC 6749 §2.3.1: Try client_secret_basic first (Authorization header)
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!String.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var encodedCredentials = authHeader.Substring(6);
                var decodedBytes = Convert.FromBase64String(encodedCredentials);
                var credentials = Encoding.UTF8.GetString(decodedBytes);
                var parts = credentials.Split(':', 2);
                
                if (parts.Length == 2)
                {
                    clientId = Uri.UnescapeDataString(parts[0]);
                    clientSecret = Uri.UnescapeDataString(parts[1]);
                    logger.LogDebug("Using client_secret_basic authentication for client {ClientId}", clientId);
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to parse Basic authorization header");
                return (null, ErrorResponse("invalid_client", "Invalid Authorization header", StatusCodes.Status401Unauthorized));
            }
        }
        // RFC 6749 §2.3.1: Try client_secret_post (form parameters)
        else if (!String.IsNullOrEmpty(clientIdForm))
        {
            clientId = clientIdForm;
            clientSecret = clientSecretForm;
            logger.LogDebug("Using client_secret_post authentication for client {ClientId}", clientId);
        }

        if (String.IsNullOrEmpty(clientId))
        {
            logger.LogWarning("No client credentials provided");
            return (null, ErrorResponse("invalid_client", "Client authentication failed", StatusCodes.Status401Unauthorized));
        }

        // Validate client credentials using IClientStore
        var client = await clientStore.ValidateClientAsync(clientId, clientSecret, cancellationToken);
        
        if (client == null)
        {
            logger.LogWarning("Client validation failed for {ClientId}", clientId);
            return (null, ErrorResponse("invalid_client", "Client authentication failed", StatusCodes.Status401Unauthorized));
        }

        return (client, null);
    }

    /// <summary>
    /// Extracts the 'jti' (JWT ID) claim from a JWT token for revocation tracking.
    /// </summary>
    private String ExtractJtiFromJwt(String jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length != 3)
                return Guid.NewGuid().ToString(); // Fallback

            var payload = parts[1];
            // Add padding if needed for base64 decoding
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }

            var jsonBytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
            var json = Encoding.UTF8.GetString(jsonBytes);
            
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("jti", out var jtiElement))
            {
                return jtiElement.GetString() ?? Guid.NewGuid().ToString();
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to extract jti from JWT");
        }

        return Guid.NewGuid().ToString(); // Fallback
    }

    /// <summary>
    /// Creates an error response per RFC 6749 §5.2.
    /// </summary>
    private static IResult ErrorResponse(String error, String errorDescription, Int32 statusCode = StatusCodes.Status400BadRequest)
    {
        return Results.Json(
            new { error, error_description = errorDescription },
            statusCode: statusCode);
    }
}
