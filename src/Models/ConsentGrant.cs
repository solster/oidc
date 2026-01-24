using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents a user's consent grant to an OIDC client application.
/// </summary>
public class ConsentGrant
{
    /// <summary>
    /// The OAuth2 client_id.
    /// </summary>
    [Required]
    public String ClientId { get; set; } = String.Empty;

    /// <summary>
    /// The user's subject identifier.
    /// </summary>
    [Required]
    public String UserId { get; set; } = String.Empty;

    /// <summary>
    /// The scopes that were granted.
    /// </summary>
    public List<String> GrantedScopes { get; set; } = new();

    /// <summary>
    /// When consent was initially granted.
    /// </summary>
    public DateTimeOffset GrantedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// When consent was last updated.
    /// </summary>
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
