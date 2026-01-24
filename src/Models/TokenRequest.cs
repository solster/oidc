using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Token endpoint request (RFC 6749 Section 4.1.3).
/// </summary>
public class TokenRequest
{
    /// <summary>
    /// The grant type (authorization_code, refresh_token).
    /// </summary>
    [Required]
    [JsonPropertyName("grant_type")]
    public String GrantType { get; set; } = String.Empty;

    /// <summary>
    /// The authorization code (for authorization_code grant).
    /// </summary>
    [JsonPropertyName("code")]
    public String? Code { get; set; }

    /// <summary>
    /// The redirect URI (must match the one from authorization request).
    /// </summary>
    [JsonPropertyName("redirect_uri")]
    public String? RedirectUri { get; set; }

    /// <summary>
    /// PKCE code verifier (for authorization_code grant).
    /// </summary>
    [JsonPropertyName("code_verifier")]
    public String? CodeVerifier { get; set; }

    /// <summary>
    /// The refresh token (for refresh_token grant).
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public String? RefreshToken { get; set; }

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
