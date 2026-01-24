using System.Security.Claims;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for providing custom claims to be included in tokens.
/// This allows consumers to inject tenant-specific or application-specific claims.
/// </summary>
public interface ITokenClaimsProvider
{
    /// <summary>
    /// Gets claims to include in the ID token.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="scopes">The granted scopes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of claims to include in the ID token.</returns>
    Task<IEnumerable<Claim>> GetIdTokenClaimsAsync(String userId, String clientId, IEnumerable<String> scopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets claims to include in the access token.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="scopes">The granted scopes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of claims to include in the access token.</returns>
    Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(String userId, String clientId, IEnumerable<String> scopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets claims to return from the UserInfo endpoint.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="scopes">The granted scopes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of claims to return from UserInfo endpoint.</returns>
    Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(String userId, IEnumerable<String> scopes, CancellationToken cancellationToken = default);
}
