using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents an authenticated user principal.
/// </summary>
public class UserPrincipal
{
    /// <summary>
    /// The user's subject identifier (sub claim).
    /// </summary>
    [Required]
    public String Subject { get; set; } = String.Empty;

    /// <summary>
    /// The user's email address.
    /// </summary>
    public String? Email { get; set; }

    /// <summary>
    /// The user's display name.
    /// </summary>
    public String? Name { get; set; }

    /// <summary>
    /// When the user authenticated.
    /// </summary>
    public DateTimeOffset AuthenticatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>
    /// Additional custom data that consumers can attach.
    /// </summary>
    public Dictionary<String, Object> AdditionalData { get; set; } = new();
}
