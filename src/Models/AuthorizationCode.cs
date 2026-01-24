using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents an OAuth2 authorization code (single-use, time-limited).
/// </summary>
public class AuthorizationCode
{
    /// <summary>
    /// The authorization code value (cryptographically random).
    /// </summary>
    [Required]
    public String Code { get; set; } = String.Empty;

    /// <summary>
    /// The OAuth2 client_id this code was issued to.
    /// </summary>
    [Required]
    public String ClientId { get; set; } = String.Empty;

    /// <summary>
    /// The user's subject identifier.
    /// </summary>
    [Required]
    public String UserId { get; set; } = String.Empty;

    /// <summary>
    /// The redirect URI from the authorization request (must match in token request).
    /// </summary>
    [Required]
    public String RedirectUri { get; set; } = String.Empty;

    /// <summary>
    /// PKCE code challenge from authorization request.
    /// </summary>
    [Required]
    public String CodeChallenge { get; set; } = String.Empty;

    /// <summary>
    /// PKCE code challenge method (S256 or plain).
    /// </summary>
    [Required]
    public String CodeChallengeMethod { get; set; } = String.Empty;

    /// <summary>
    /// The scopes that were authorized.
    /// </summary>
    public List<String> RequestedScopes { get; set; } = new();

    /// <summary>
    /// The nonce from the authorization request (included in ID token).
    /// </summary>
    public String? Nonce { get; set; }

    /// <summary>
    /// When this code expires (typically 5 minutes from creation).
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// When this code was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Whether this code has been consumed (single-use enforcement).
    /// </summary>
    public Boolean IsConsumed { get; set; }

    /// <summary>
    /// When this code was consumed.
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }
}
