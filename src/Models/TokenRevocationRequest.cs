using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Token revocation request (RFC 7009).
/// </summary>
public class TokenRevocationRequest
{
    /// <summary>
    /// The token to revoke.
    /// </summary>
    [Required]
    [JsonPropertyName("token")]
    public String Token { get; set; } = String.Empty;

    /// <summary>
    /// A hint about the type of token (access_token or refresh_token).
    /// </summary>
    [JsonPropertyName("token_type_hint")]
    public String? TokenTypeHint { get; set; }

    /// <summary>
    /// The client ID (for client authentication).
    /// </summary>
    [JsonPropertyName("client_id")]
    public String? ClientId { get; set; }

    /// <summary>
    /// The client secret (for client authentication).
    /// </summary>
    [JsonPropertyName("client_secret")]
    public String? ClientSecret { get; set; }
}
