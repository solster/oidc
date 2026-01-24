using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for tracking access tokens to support revocation.
/// Since access tokens are JWTs, we store references by their 'jti' claim to check revocation status.
/// </summary>
public interface IAccessTokenStore
{
    /// <summary>
    /// Saves an access token reference for revocation tracking.
    /// </summary>
    /// <param name="token">The access token reference to save.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The saved token reference.</returns>
    Task<AccessTokenReference> SaveTokenAsync(AccessTokenReference token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes an access token by its token ID (jti claim).
    /// </summary>
    /// <param name="tokenId">The token ID (jti claim value).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if revoked, false if not found.</returns>
    Task<Boolean> RevokeTokenAsync(String tokenId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if an access token has been revoked.
    /// </summary>
    /// <param name="tokenId">The token ID (jti claim value).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if revoked, false otherwise.</returns>
    Task<Boolean> IsRevokedAsync(String tokenId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all access tokens issued from a specific authorization code.
    /// Required by RFC 6749 §10.5 when authorization code reuse is detected.
    /// </summary>
    /// <param name="authorizationCode">The authorization code value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of tokens revoked.</returns>
    Task<Int32> RevokeTokensByAuthorizationCodeAsync(String authorizationCode, CancellationToken cancellationToken = default);
}
