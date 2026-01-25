using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents an OAuth2/OIDC client application.
/// </summary>
public class OAuthClient
{
    /// <summary>
    /// Internal unique identifier.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// OAuth2 client_id (public identifier).
    /// </summary>
    [Required]
    public String ClientId { get; set; } = String.Empty;

    /// <summary>
    /// Human-readable client name.
    /// </summary>
    [Required]
    public String ClientName { get; set; } = String.Empty;

    /// <summary>
    /// Client type (Confidential or Public).
    /// </summary>
    public ClientType ClientType { get; set; }

    /// <summary>
    /// Allowed redirect URIs for this client.
    /// </summary>
    public List<String> RedirectUris { get; set; } = new();

    /// <summary>
    /// Allowed post-logout redirect URIs for this client.
    /// Per OIDC Session Management 1.0 §5.
    /// </summary>
    public List<String> PostLogoutRedirectUris { get; set; } = new();

    /// <summary>
    /// Allowed scopes for this client.
    /// </summary>
    public List<String> AllowedScopes { get; set; } = new();

    /// <summary>
    /// Indicates if this client was registered dynamically (RFC 7591).
    /// </summary>
    public Boolean IsDynamic { get; set; }

    /// <summary>
    /// Registration access token for dynamic clients (RFC 7592).
    /// </summary>
    public String? RegistrationAccessToken { get; set; }

    /// <summary>
    /// Client secrets (for confidential clients). Multiple secrets can be active simultaneously.
    /// </summary>
    public List<ClientSecret> Secrets { get; set; } = new();

    /// <summary>
    /// When the client was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// When the client was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Client type enumeration.
/// </summary>
public enum ClientType
{
    /// <summary>
    /// Public clients (SPAs, mobile apps) - cannot securely store secrets.
    /// </summary>
    Public = 0,

    /// <summary>
    /// Confidential clients (server-side apps) - can securely store secrets.
    /// </summary>
    Confidential = 1
}
