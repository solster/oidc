using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for managing user consent to OIDC client applications.
/// </summary>
public interface IConsentService
{
    /// <summary>
    /// Determines whether a user needs to grant consent for a client to access requested scopes.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="requestedScopes">The scopes being requested.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if consent is required, false if already granted.</returns>
    Task<Boolean> RequiresConsentAsync(String userId, String clientId, IEnumerable<String> requestedScopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Grants user consent for a client to access specific scopes.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="grantedScopes">The scopes being granted.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created consent grant.</returns>
    Task<ConsentGrant> GrantConsentAsync(String userId, String clientId, IEnumerable<String> grantedScopes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes user consent for a client.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if consent was revoked, false if no consent existed.</returns>
    Task<Boolean> RevokeConsentAsync(String userId, String clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists all consent grants for a user.
    /// </summary>
    /// <param name="userId">The user's subject identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of consent grants.</returns>
    Task<IEnumerable<ConsentGrant>> ListUserConsentsAsync(String userId, CancellationToken cancellationToken = default);
}
