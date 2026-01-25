using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Token introspection response per RFC 7662 §2.2.
/// </summary>
public class TokenIntrospectionResponse
{
    /// <summary>
    /// REQUIRED. Boolean indicator of whether or not the presented token is currently active.
    /// </summary>
    [JsonPropertyName("active")]
    public Boolean Active { get; set; }

    /// <summary>
    /// OPTIONAL. A space-separated list of scopes associated with this token.
    /// </summary>
    [JsonPropertyName("scope")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? Scope { get; set; }

    /// <summary>
    /// OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
    /// </summary>
    [JsonPropertyName("client_id")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? ClientId { get; set; }

    /// <summary>
    /// OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
    /// </summary>
    [JsonPropertyName("username")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? Username { get; set; }

    /// <summary>
    /// OPTIONAL. Type of the token as defined in RFC 6749 Section 7.1.
    /// </summary>
    [JsonPropertyName("token_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? TokenType { get; set; }

    /// <summary>
    /// OPTIONAL. Integer timestamp, measured in seconds since January 1 1970 UTC,
    /// indicating when this token will expire.
    /// </summary>
    [JsonPropertyName("exp")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Int64? Exp { get; set; }

    /// <summary>
    /// OPTIONAL. Integer timestamp, measured in seconds since January 1 1970 UTC,
    /// indicating when this token was originally issued.
    /// </summary>
    [JsonPropertyName("iat")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Int64? Iat { get; set; }

    /// <summary>
    /// OPTIONAL. Subject of the token, as defined in JWT [RFC7519] Section 4.1.2.
    /// Usually a machine-readable identifier of the resource owner who authorized this token.
    /// </summary>
    [JsonPropertyName("sub")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? Sub { get; set; }

    /// <summary>
    /// OPTIONAL. Service-specific string identifier or list of string identifiers
    /// representing the intended audience for this token.
    /// </summary>
    [JsonPropertyName("aud")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? Aud { get; set; }

    /// <summary>
    /// OPTIONAL. String representing the issuer of this token, as defined in JWT [RFC7519] Section 4.1.1.
    /// </summary>
    [JsonPropertyName("iss")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? Iss { get; set; }

    /// <summary>
    /// OPTIONAL. String identifier for the token, as defined in JWT [RFC7519] Section 4.1.7.
    /// </summary>
    [JsonPropertyName("jti")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public String? Jti { get; set; }
}
