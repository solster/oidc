using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents a refresh token with rotation and family tracking for breach detection.
/// </summary>
public class RefreshToken
{
    /// <summary>
    /// The hashed token value.
    /// </summary>
    [Required]
    public String TokenHash { get; set; } = String.Empty;

    /// <summary>
    /// The OAuth2 client_id this token was issued to.
    /// </summary>
    [Required]
    public String ClientId { get; set; } = String.Empty;

    /// <summary>
    /// The user's subject identifier.
    /// </summary>
    [Required]
    public String UserId { get; set; } = String.Empty;

    /// <summary>
    /// The parent token hash (for rotation tracking).
    /// </summary>
    public String? ParentTokenHash { get; set; }

    /// <summary>
    /// Token family identifier for breach detection.
    /// All tokens in a rotation chain share the same family GUID.
    /// </summary>
    public Guid TokenFamily { get; set; }

    /// <summary>
    /// The scopes granted with this token.
    /// </summary>
    public List<String> Scopes { get; set; } = new();

    /// <summary>
    /// When this token expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; set; }

    /// <summary>
    /// When this token was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// When this token was consumed (used to get a new token).
    /// </summary>
    public DateTimeOffset? ConsumedAt { get; set; }

    /// <summary>
    /// When this token was revoked.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; set; }

    /// <summary>
    /// Reason for revocation (e.g., "User logout", "Breach detected", "Admin revocation").
    /// </summary>
    public String? RevokedReason { get; set; }
}
