using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Dynamic client registration response (RFC 7591).
/// </summary>
public class DynamicClientRegistrationResponse
{
    /// <summary>
    /// The client identifier.
    /// </summary>
    [JsonPropertyName("client_id")]
    public String ClientId { get; set; } = String.Empty;

    /// <summary>
    /// The client secret (only for confidential clients).
    /// </summary>
    [JsonPropertyName("client_secret")]
    public String? ClientSecret { get; set; }

    /// <summary>
    /// Time at which the client identifier was issued (Unix timestamp).
    /// </summary>
    [JsonPropertyName("client_id_issued_at")]
    public Int64 ClientIdIssuedAt { get; set; }

    /// <summary>
    /// Registration access token for managing this client (RFC 7592).
    /// </summary>
    [JsonPropertyName("registration_access_token")]
    public String? RegistrationAccessToken { get; set; }

    /// <summary>
    /// Location of the client configuration endpoint (RFC 7592).
    /// </summary>
    [JsonPropertyName("registration_client_uri")]
    public String? RegistrationClientUri { get; set; }

    /// <summary>
    /// Human-readable client name.
    /// </summary>
    [JsonPropertyName("client_name")]
    public String? ClientName { get; set; }

    /// <summary>
    /// Array of redirect URIs.
    /// </summary>
    [JsonPropertyName("redirect_uris")]
    public List<String> RedirectUris { get; set; } = new();

    /// <summary>
    /// OAuth 2.0 grant types.
    /// </summary>
    [JsonPropertyName("grant_types")]
    public List<String> GrantTypes { get; set; } = new();

    /// <summary>
    /// OAuth 2.0 response types.
    /// </summary>
    [JsonPropertyName("response_types")]
    public List<String> ResponseTypes { get; set; } = new();

    /// <summary>
    /// Token endpoint authentication method.
    /// </summary>
    [JsonPropertyName("token_endpoint_auth_method")]
    public String? TokenEndpointAuthMethod { get; set; }
}
