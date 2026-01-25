using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Token introspection request per RFC 7662 §2.1.
/// </summary>
public class TokenIntrospectionRequest
{
    /// <summary>
    /// The token to introspect.
    /// REQUIRED per RFC 7662 §2.1.
    /// </summary>
    [Required]
    [JsonPropertyName("token")]
    public String Token { get; set; } = String.Empty;

    /// <summary>
    /// A hint about the type of the token submitted for introspection.
    /// Valid values: "access_token" or "refresh_token".
    /// OPTIONAL per RFC 7662 §2.1.
    /// </summary>
    [JsonPropertyName("token_type_hint")]
    public String? TokenTypeHint { get; set; }

    /// <summary>
    /// Client identifier for authentication.
    /// REQUIRED per RFC 7662 §2.1 (client authentication required).
    /// </summary>
    [JsonPropertyName("client_id")]
    public String? ClientId { get; set; }

    /// <summary>
    /// Client secret for authentication.
    /// REQUIRED for confidential clients per RFC 6749 §2.3.1.
    /// </summary>
    [JsonPropertyName("client_secret")]
    public String? ClientSecret { get; set; }
}
