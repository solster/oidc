using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Handlers;

/// <summary>
/// Handles OAuth2/OIDC authorization requests with PKCE support.
/// </summary>
public class AuthorizeEndpointHandler(
    IClientStore clientStore,
    IResourceOwnerAuthenticator authenticator,
    IConsentService consentService,
    IAuthorizationCodeStore codeStore,
    OpenIdConnectOptions options,
    ILogger<AuthorizeEndpointHandler> logger)
{
    public async Task<IResult> HandleAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        logger.LogInformation("Authorization request from {RemoteIp}", context.Connection.RemoteIpAddress?.ToString());

        var query = context.Request.Query;

        // Extract and validate OAuth2 parameters
        var responseType = query["response_type"].ToString();
        var clientId = query["client_id"].ToString();
        var redirectUri = query["redirect_uri"].ToString();
        var scope = query["scope"].ToString();
        var state = query["state"].ToString();
        var nonce = query["nonce"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        // Validate response_type
        if (String.IsNullOrEmpty(responseType) || responseType != "code")
        {
            logger.LogWarning("Invalid or unsupported response_type: {ResponseType}", responseType);
            return Results.BadRequest(new { error = "unsupported_response_type", error_description = "Only 'code' response type is supported" });
        }

        // Validate client_id
        if (String.IsNullOrEmpty(clientId))
        {
            logger.LogWarning("Missing client_id");
            return Results.BadRequest(new { error = "invalid_request", error_description = "client_id is required" });
        }

        // Validate redirect_uri
        if (String.IsNullOrEmpty(redirectUri))
        {
            logger.LogWarning("Missing redirect_uri for client {ClientId}", clientId);
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri is required" });
        }

        // RFC 6749 §3.1.2: Redirect URI MUST NOT contain a fragment component
        if (redirectUri.Contains('#'))
        {
            logger.LogWarning("Redirect URI contains fragment for client {ClientId}", clientId);
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri must not contain a fragment component" });
        }

        // Validate client
        var client = await clientStore.GetByClientIdAsync(clientId, cancellationToken);
        if (client == null)
        {
            logger.LogWarning("Client not found: {ClientId}", clientId);
            return Results.BadRequest(new { error = "invalid_client", error_description = "Client not found" });
        }

        // RFC 6749 §3.1.2.2: Redirect URI matching MUST be exact (case-sensitive)
        if (!client.RedirectUris.Any(uri => uri.Equals(redirectUri, StringComparison.Ordinal)))
        {
            logger.LogWarning("Redirect URI mismatch for client {ClientId}. Provided: {RedirectUri}", clientId, redirectUri);
            return Results.BadRequest(new { error = "invalid_request", error_description = "redirect_uri does not match any registered URIs" });
        }

        // From this point, we can redirect errors to the client's redirect_uri

        // Validate scope contains 'openid' and remove duplicates (RFC 6749 §3.3)
        var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();
        if (scopes.Count == 0)
        {
            logger.LogWarning("Empty scope for client {ClientId}", clientId);
            return RedirectWithError(redirectUri, "invalid_request", "scope parameter is required", state);
        }

        if (!scopes.Contains("openid"))
        {
            logger.LogWarning("Missing 'openid' scope for client {ClientId}", clientId);
            return RedirectWithError(redirectUri, "invalid_scope", "The 'openid' scope is required", state);
        }

        // Validate requested scopes are allowed for this client
        var invalidScopes = scopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
        if (invalidScopes.Any())
        {
            logger.LogWarning("Client {ClientId} requested invalid scopes: {InvalidScopes}", clientId, String.Join(", ", invalidScopes));
            return RedirectWithError(redirectUri, "invalid_scope", $"Invalid scopes: {String.Join(", ", invalidScopes)}", state);
        }

        // Validate PKCE parameters
        if (options.RequirePkce)
        {
            if (String.IsNullOrEmpty(codeChallenge))
            {
                logger.LogWarning("Missing code_challenge for client {ClientId}", clientId);
                return RedirectWithError(redirectUri, "invalid_request", "code_challenge is required", state);
            }

            if (String.IsNullOrEmpty(codeChallengeMethod) || codeChallengeMethod != "S256")
            {
                logger.LogWarning("Invalid or unsupported code_challenge_method for client {ClientId}: {Method}", clientId, codeChallengeMethod);
                return RedirectWithError(redirectUri, "invalid_request", "code_challenge_method must be S256", state);
            }

            // Validate code_challenge format (base64url)
            if (!IsValidBase64Url(codeChallenge))
            {
                logger.LogWarning("Invalid code_challenge format for client {ClientId}", clientId);
                return RedirectWithError(redirectUri, "invalid_request", "code_challenge must be base64url encoded", state);
            }
        }

        // Validate nonce (recommended for implicit/hybrid flows, but good practice for code flow too)
        if (String.IsNullOrEmpty(nonce))
        {
            logger.LogWarning("Missing nonce for client {ClientId}", clientId);
            return RedirectWithError(redirectUri, "invalid_request", "nonce is required", state);
        }

        // Check authentication
        var user = await authenticator.GetCurrentUserAsync(context, cancellationToken);
        if (user == null)
        {
            logger.LogInformation("User not authenticated, redirecting to login for client {ClientId}", clientId);
            var returnUrl = context.Request.Path + context.Request.QueryString;
            var loginUrl = $"{options.LoginPath}?return_url={Uri.EscapeDataString(returnUrl)}";
            return Results.Redirect(loginUrl);
        }

        logger.LogInformation("User {UserId} authenticated for client {ClientId}", user.Subject, clientId);

        // Check consent
        var requiresConsent = await consentService.RequiresConsentAsync(user.Subject, clientId, scopes, cancellationToken);
        if (requiresConsent)
        {
            logger.LogInformation("User {UserId} needs to grant consent for client {ClientId}", user.Subject, clientId);
            var returnUrl = context.Request.Path + context.Request.QueryString;
            var consentUrl = $"{options.ConsentPath}?return_url={Uri.EscapeDataString(returnUrl)}";
            return Results.Redirect(consentUrl);
        }

        logger.LogInformation("User {UserId} has granted consent for client {ClientId}", user.Subject, clientId);

        // Generate authorization code
        var code = GenerateSecureCode();
        var authorizationCode = new AuthorizationCode
        {
            Code = code,
            ClientId = clientId,
            UserId = user.Subject,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            RequestedScopes = scopes,
            Nonce = nonce,
            ExpiresAt = DateTimeOffset.UtcNow.Add(options.AuthorizationCodeLifetime),
            CreatedAt = DateTimeOffset.UtcNow,
            IsConsumed = false
        };

        await codeStore.CreateCodeAsync(authorizationCode, cancellationToken);

        logger.LogInformation("Authorization code generated for user {UserId} and client {ClientId}", user.Subject, clientId);

        // Redirect back to client with authorization code
        var callbackUrl = AddQueryParameter(redirectUri, "code", code);
        if (!String.IsNullOrEmpty(state))
        {
            callbackUrl = AddQueryParameter(callbackUrl, "state", state);
        }

        return Results.Redirect(callbackUrl);
    }

    private static IResult RedirectWithError(String redirectUri, String error, String errorDescription, String? state)
    {
        var errorUrl = AddQueryParameter(redirectUri, "error", error);
        errorUrl = AddQueryParameter(errorUrl, "error_description", errorDescription);
        if (!String.IsNullOrEmpty(state))
        {
            errorUrl = AddQueryParameter(errorUrl, "state", state);
        }
        return Results.Redirect(errorUrl);
    }

    private static String AddQueryParameter(String url, String key, String value)
    {
        var uriBuilder = new UriBuilder(url);
        var query = QueryHelpers.ParseQuery(uriBuilder.Query);
        query[key] = value;
        uriBuilder.Query = QueryHelpers.AddQueryString(String.Empty, query).TrimStart('?');
        return uriBuilder.ToString();
    }

    private static String GenerateSecureCode()
    {
        var bytes = new Byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    private static Boolean IsValidBase64Url(String input)
    {
        if (String.IsNullOrEmpty(input))
            return false;

        // RFC 7636 §4.3: code_challenge MUST be 43-128 characters
        if (input.Length < 43 || input.Length > 128)
            return false;

        // Base64url characters: A-Z, a-z, 0-9, -, _
        foreach (var c in input)
        {
            if (!Char.IsLetterOrDigit(c) && c != '-' && c != '_')
                return false;
        }

        return true;
    }

    /// <summary>
    /// Validates a PKCE code_verifier against a code_challenge using S256 method.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    public static Boolean ValidatePkceChallenge(String codeVerifier, String codeChallenge, String codeChallengeMethod)
    {
        if (codeChallengeMethod == "S256")
        {
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
            var computedChallenge = Convert.ToBase64String(hash)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
            
            // Use constant-time comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(computedChallenge),
                Encoding.UTF8.GetBytes(codeChallenge)
            );
        }
        else if (codeChallengeMethod == "plain")
        {
            // Use constant-time comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(codeVerifier),
                Encoding.UTF8.GetBytes(codeChallenge)
            );
        }

        return false;
    }
}
