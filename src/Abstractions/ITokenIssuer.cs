using System.Security.Claims;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for issuing OAuth2/OIDC tokens (ID tokens, access tokens, refresh tokens).
/// </summary>
public interface ITokenIssuer
{
    /// <summary>
    /// Issues an ID token (JWT) containing user identity information.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id (audience).</param>
    /// <param name="nonce">The nonce from the authorization request.</param>
    /// <param name="authTime">The time when user authentication occurred.</param>
    /// <param name="additionalClaims">Additional claims to include in the token.</param>
    /// <param name="lifetime">The token lifetime.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The serialized ID token (JWT).</returns>
    Task<String> IssueIdTokenAsync(
        String userId,
        String clientId,
        String? nonce,
        DateTimeOffset authTime,
        IEnumerable<Claim> additionalClaims,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues an access token (JWT) for accessing protected resources.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="scopes">The granted scopes.</param>
    /// <param name="additionalClaims">Additional claims to include in the token.</param>
    /// <param name="lifetime">The token lifetime.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The serialized access token (JWT).</returns>
    Task<String> IssueAccessTokenAsync(
        String userId,
        String clientId,
        IEnumerable<String> scopes,
        IEnumerable<Claim> additionalClaims,
        TimeSpan lifetime,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Issues a refresh token (opaque) for obtaining new access tokens.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="scopes">The granted scopes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The opaque refresh token string.</returns>
    Task<String> IssueRefreshTokenAsync(
        String userId,
        String clientId,
        IEnumerable<String> scopes,
        CancellationToken cancellationToken = default);
}
