using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Token endpoint response (RFC 6749 Section 5.1, OIDC Core Section 3.1.3.3).
/// </summary>
public class TokenResponse
{
    /// <summary>
    /// The ID token (JWT).
    /// </summary>
    [JsonPropertyName("id_token")]
    public String? IdToken { get; set; }

    /// <summary>
    /// The access token (JWT).
    /// </summary>
    [JsonPropertyName("access_token")]
    public String AccessToken { get; set; } = String.Empty;

    /// <summary>
    /// The token type (always "Bearer").
    /// </summary>
    [JsonPropertyName("token_type")]
    public String TokenType { get; set; } = "Bearer";

    /// <summary>
    /// The access token lifetime in seconds.
    /// </summary>
    [JsonPropertyName("expires_in")]
    public Int32 ExpiresIn { get; set; }

    /// <summary>
    /// The refresh token (opaque).
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public String? RefreshToken { get; set; }

    /// <summary>
    /// The granted scopes (space-separated).
    /// </summary>
    [JsonPropertyName("scope")]
    public String? Scope { get; set; }
}
