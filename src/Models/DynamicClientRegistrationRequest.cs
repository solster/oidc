using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Dynamic client registration request (RFC 7591).
/// </summary>
public class DynamicClientRegistrationRequest
{
    /// <summary>
    /// Array of redirect URIs.
    /// </summary>
    [JsonPropertyName("redirect_uris")]
    public List<String> RedirectUris { get; set; } = new();

    /// <summary>
    /// Human-readable client name.
    /// </summary>
    [JsonPropertyName("client_name")]
    public String? ClientName { get; set; }

    /// <summary>
    /// OAuth 2.0 grant types (e.g., "authorization_code", "refresh_token").
    /// </summary>
    [JsonPropertyName("grant_types")]
    public List<String> GrantTypes { get; set; } = new() { "authorization_code" };

    /// <summary>
    /// OAuth 2.0 response types (e.g., "code").
    /// </summary>
    [JsonPropertyName("response_types")]
    public List<String> ResponseTypes { get; set; } = new() { "code" };

    /// <summary>
    /// Space-separated list of scope values.
    /// </summary>
    [JsonPropertyName("scope")]
    public String? Scope { get; set; }

    /// <summary>
    /// Token endpoint authentication method (e.g., "client_secret_basic", "client_secret_post", "none").
    /// </summary>
    [JsonPropertyName("token_endpoint_auth_method")]
    public String? TokenEndpointAuthMethod { get; set; }
}
