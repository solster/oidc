using System.Text.Json.Serialization;

namespace Solster.Authentication.OpenIdConnect.Models;

/// <summary>
/// Represents an end session request per OIDC Session Management 1.0 §5.
/// Used for RP-Initiated Logout.
/// </summary>
public class EndSessionRequest
{
    /// <summary>
    /// ID Token previously issued by the OP to the RP.
    /// RECOMMENDED. Used to identify the session to be ended.
    /// </summary>
    [JsonPropertyName("id_token_hint")]
    public String? IdTokenHint { get; set; }

    /// <summary>
    /// URI to which the RP is requesting that the End-User's User Agent be redirected after logout.
    /// OPTIONAL. Must be registered in the client's PostLogoutRedirectUris list.
    /// </summary>
    [JsonPropertyName("post_logout_redirect_uri")]
    public String? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Opaque value used by the RP to maintain state between the logout request and callback.
    /// RECOMMENDED when post_logout_redirect_uri is used.
    /// </summary>
    [JsonPropertyName("state")]
    public String? State { get; set; }
}
