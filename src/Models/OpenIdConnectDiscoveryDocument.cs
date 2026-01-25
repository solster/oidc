using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents an OpenID Connect Discovery Document (RFC 8414)
/// </summary>
public class OpenIdConnectDiscoveryDocument
{
    [JsonPropertyName("issuer")]
    public String Issuer { get; set; } = String.Empty;

    [JsonPropertyName("authorization_endpoint")]
    public String AuthorizationEndpoint { get; set; } = String.Empty;

    [JsonPropertyName("token_endpoint")]
    public String TokenEndpoint { get; set; } = String.Empty;

    [JsonPropertyName("userinfo_endpoint")]
    public String UserInfoEndpoint { get; set; } = String.Empty;

    [JsonPropertyName("revocation_endpoint")]
    public String? RevocationEndpoint { get; set; }

    [JsonPropertyName("introspection_endpoint")]
    public String? IntrospectionEndpoint { get; set; }

    [JsonPropertyName("jwks_uri")]
    public String JwksUri { get; set; } = String.Empty;

    [JsonPropertyName("response_types_supported")]
    public List<String> ResponseTypesSupported { get; set; } = new();

    [JsonPropertyName("subject_types_supported")]
    public List<String> SubjectTypesSupported { get; set; } = new();

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    public List<String> IdTokenSigningAlgValuesSupported { get; set; } = new();

    [JsonPropertyName("scopes_supported")]
    public List<String> ScopesSupported { get; set; } = new();

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    public List<String> TokenEndpointAuthMethodsSupported { get; set; } = new();

    [JsonPropertyName("revocation_endpoint_auth_methods_supported")]
    public List<String>? RevocationEndpointAuthMethodsSupported { get; set; }

    [JsonPropertyName("introspection_endpoint_auth_methods_supported")]
    public List<String>? IntrospectionEndpointAuthMethodsSupported { get; set; }
}
