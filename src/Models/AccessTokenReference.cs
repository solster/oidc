using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents a reference to an access token for revocation tracking.
/// Since access tokens are JWTs, we track them by their 'jti' (JWT ID) claim.
/// </summary>
public class AccessTokenReference
{
    /// <summary>
    /// The token ID from the 'jti' claim in the JWT.
    /// </summary>
    [Required]
    public String TokenId { get; set; } = String.Empty;

    /// <summary>
    /// The user's subject identifier.
    /// </summary>
    [Required]
    public String UserId { get; set; } = String.Empty;

    /// <summary>
    /// The OAuth2 client_id this token was issued to.
    /// </summary>
    [Required]
    public String ClientId { get; set; } = String.Empty;

    /// <summary>
    /// When this token expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// When this token was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// When this token was revoked.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }
}
