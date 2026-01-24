using System.ComponentModel.DataAnnotations;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents a client secret for confidential clients.
/// Multiple secrets can be active to support secret rotation.
/// </summary>
public class ClientSecret
{
    /// <summary>
    /// Unique identifier for this secret.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// The hashed secret value (never store plaintext).
    /// </summary>
    [Required]
    public String SecretHash { get; set; } = String.Empty;

    /// <summary>
    /// Optional description for this secret (e.g., "Production server", "Staging").
    /// </summary>
    public String? Description { get; set; }

    /// <summary>
    /// When this secret was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
