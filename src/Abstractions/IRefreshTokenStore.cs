using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for storing and managing refresh tokens with rotation support.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>
    /// Saves a refresh token.
    /// </summary>
    /// <param name="token">The refresh token to save.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The saved refresh token.</returns>
    Task<RefreshToken> SaveTokenAsync(RefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Consumes a refresh token and rotates it (issues a new one in the same family).
    /// If the token has already been consumed (potential breach), this should revoke the entire token family.
    /// </summary>
    /// <param name="tokenValue">The refresh token value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The consumed token if valid, otherwise null.</returns>
    Task<RefreshToken?> ConsumeAndRotateAsync(String tokenValue, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a specific refresh token.
    /// </summary>
    /// <param name="tokenValue">The refresh token value.</param>
    /// <param name="reason">The reason for revocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if revoked, false if not found.</returns>
    Task<Boolean> RevokeTokenAsync(String tokenValue, String? reason = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a refresh token by its token hash.
    /// </summary>
    /// <param name="tokenHash">The token hash.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refresh token if found, otherwise null.</returns>
    Task<RefreshToken?> GetByTokenHashAsync(String tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all refresh tokens for a specific client and user.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="reason">The reason for revocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of tokens revoked.</returns>
    Task<Int32> RevokeAllForClientAsync(String userId, String clientId, String? reason = null, CancellationToken cancellationToken = default);
}
