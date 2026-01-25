namespace Solster.Authentication.OpenIdConnect;

public class OpenIdConnectOptions
{
    // Issuer and Origin
    public String Issuer { get; set; } = String.Empty; // required
    public String? PublicOrigin { get; set; }
    
    // Audience Validation
    public String UserInfoAudience { get; set; } = "userinfo"; // Default audience for UserInfo endpoint
    public Boolean ValidateUserInfoAudience { get; set; } = true; // Enable audience validation by default

    // Endpoint Paths
    public String AuthorizationPath { get; set; } = "/connect/authorize";
    public String TokenPath { get; set; } = "/connect/token";
    public String UserInfoPath { get; set; } = "/connect/userinfo";
    public String JwksPath { get; set; } = "/.well-known/jwks.json";
    public String RevocationPath { get; set; } = "/connect/revoke";
    public String IntrospectionPath { get; set; } = "/connect/introspect";

    // UI Paths
    public String LoginPath { get; set; } = "/login";
    public String ConsentPath { get; set; } = "/connect/consent";

    // Supported Features (for discovery document)
    public List<String> SupportedScopes { get; set; } = ["openid", "profile", "email"];
    public List<String> SupportedResponseTypes { get; set; } = ["code"];
    public List<String> SupportedSubjectTypes { get; set; } = ["public"];
    public List<String> SupportedIdTokenSigningAlgValues { get; set; } = ["RS256"];
    public List<String> SupportedTokenEndpointAuthMethods { get; set; } =
        ["client_secret_basic", "client_secret_post", "none"];

    // Token Lifetimes
    public TimeSpan AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(30);
    public TimeSpan IdTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    // Feature Flags
    public Boolean RequirePkce { get; set; } = true;
    public Boolean EnableRefreshTokenRotation { get; set; } = true;
    public Boolean EnableDynamicClientRegistration { get; set; } = true;
    public Boolean AllowInsecureHttpInDevelopment { get; set; } = false;

    // Security Settings
    public TimeSpan MaxRefreshTokenReuseDetectionWindow { get; set; } = TimeSpan.FromSeconds(10);
    public String ClientManagementPolicy { get; set; } = "Owner";

    // Caching and Rate Limiting
    public TimeSpan DiscoveryCacheDuration { get; set; } = TimeSpan.FromSeconds(3600);

    public Int32 RateLimitRequests { get; set; } = 60;
    public TimeSpan RateLimitWindow { get; set; } = TimeSpan.FromMinutes(1);
}