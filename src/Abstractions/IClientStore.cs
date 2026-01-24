using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for storing and retrieving OIDC client applications.
/// </summary>
public interface IClientStore
{
    /// <summary>
    /// Gets a client by its internal ID.
    /// </summary>
    /// <param name="id">The internal client ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The client if found, otherwise null.</returns>
    Task<OAuthClient?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a client by its OAuth2 client_id.
    /// </summary>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The client if found, otherwise null.</returns>
    Task<OAuthClient?> GetByClientIdAsync(String clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new OIDC client application.
    /// </summary>
    /// <param name="client">The client to create.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created client.</returns>
    Task<OAuthClient> CreateAsync(OAuthClient client, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing OIDC client application.
    /// </summary>
    /// <param name="client">The client to update.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The updated client.</returns>
    Task<OAuthClient> UpdateAsync(OAuthClient client, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a client by its internal ID.
    /// </summary>
    /// <param name="id">The internal client ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if deleted, false if not found.</returns>
    Task<Boolean> DeleteAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates client credentials (client_id and optional client_secret).
    /// </summary>
    /// <param name="clientId">The OAuth2 client_id.</param>
    /// <param name="clientSecret">The client secret (null for public clients).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validated client if credentials are valid, otherwise null.</returns>
    Task<OAuthClient?> ValidateClientAsync(String clientId, String? clientSecret = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists all registered clients.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of all clients.</returns>
    Task<IEnumerable<OAuthClient>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new secret to a client.
    /// </summary>
    /// <param name="clientId">The internal client ID.</param>
    /// <param name="secret">The client secret to add.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created secret.</returns>
    Task<ClientSecret> AddSecretAsync(Guid clientId, ClientSecret secret, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a secret from a client.
    /// </summary>
    /// <param name="clientId">The internal client ID.</param>
    /// <param name="secretId">The secret ID to remove.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if removed, false if not found.</returns>
    Task<Boolean> RemoveSecretAsync(Guid clientId, Guid secretId, CancellationToken cancellationToken = default);
}
