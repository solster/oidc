using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests;

public class OpenIdConnectOptionsTests
{
    [Fact]
    public void OpenIdConnectOptions_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var options = new OpenIdConnectOptions
        {
            Issuer = "https://issuer.example.com"
        };

        // Assert
        options.Issuer.Should().Be("https://issuer.example.com");
        options.PublicOrigin.Should().BeNull();
        
        // Endpoint paths
        options.AuthorizationPath.Should().Be("/connect/authorize");
        options.TokenPath.Should().Be("/connect/token");
        options.UserInfoPath.Should().Be("/connect/userinfo");
        options.JwksPath.Should().Be("/.well-known/jwks.json");
        options.RevocationPath.Should().Be("/connect/revoke");
        
        // UI paths
        options.LoginPath.Should().Be("/login");
        options.ConsentPath.Should().Be("/connect/consent");
        
        // Supported features
        options.SupportedScopes.Should().Contain("openid");
        options.SupportedScopes.Should().Contain("profile");
        options.SupportedScopes.Should().Contain("email");
        options.SupportedResponseTypes.Should().Contain("code");
        options.SupportedIdTokenSigningAlgValues.Should().Contain("RS256");
        options.SupportedTokenEndpointAuthMethods.Should().Contain("client_secret_basic");
        options.SupportedTokenEndpointAuthMethods.Should().Contain("client_secret_post");
        options.SupportedTokenEndpointAuthMethods.Should().Contain("none");
        
        // Token lifetimes
        options.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromMinutes(5));
        options.AccessTokenLifetime.Should().Be(TimeSpan.FromHours(1));
        options.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(30));
        options.IdTokenLifetime.Should().Be(TimeSpan.FromHours(1));
        
        // Feature flags
        options.RequirePkce.Should().BeTrue();
        options.EnableRefreshTokenRotation.Should().BeTrue();
        options.EnableDynamicClientRegistration.Should().BeTrue();
        options.AllowInsecureHttpInDevelopment.Should().BeFalse();
        
        // Security settings
        options.MaxRefreshTokenReuseDetectionWindow.Should().Be(TimeSpan.FromSeconds(10));
        options.ClientManagementPolicy.Should().Be("Owner");
        
        // Rate limiting
        options.RateLimitRequests.Should().Be(60);
        options.RateLimitWindow.Should().Be(TimeSpan.FromMinutes(1));
    }

    [Fact]
    public void OpenIdConnectOptions_CanBeConfigured()
    {
        // Arrange & Act
        var options = new OpenIdConnectOptions
        {
            Issuer = "https://custom-issuer.com",
            PublicOrigin = "https://public.example.com",
            AuthorizationPath = "/custom/authorize",
            TokenPath = "/custom/token",
            LoginPath = "/custom-login",
            ConsentPath = "/custom-consent",
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(10),
            AccessTokenLifetime = TimeSpan.FromHours(2),
            RequirePkce = false,
            EnableDynamicClientRegistration = false,
            ClientManagementPolicy = "Admin"
        };

        // Assert
        options.Issuer.Should().Be("https://custom-issuer.com");
        options.PublicOrigin.Should().Be("https://public.example.com");
        options.AuthorizationPath.Should().Be("/custom/authorize");
        options.TokenPath.Should().Be("/custom/token");
        options.LoginPath.Should().Be("/custom-login");
        options.ConsentPath.Should().Be("/custom-consent");
        options.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromMinutes(10));
        options.AccessTokenLifetime.Should().Be(TimeSpan.FromHours(2));
        options.RequirePkce.Should().BeFalse();
        options.EnableDynamicClientRegistration.Should().BeFalse();
        options.ClientManagementPolicy.Should().Be("Admin");
    }

    [Fact]
    public void OpenIdConnectOptions_TokenLifetimes_CanBeCustomized()
    {
        // Arrange & Act
        var options = new OpenIdConnectOptions
        {
            Issuer = "https://issuer.example.com",
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(3),
            AccessTokenLifetime = TimeSpan.FromMinutes(30),
            RefreshTokenLifetime = TimeSpan.FromDays(7),
            IdTokenLifetime = TimeSpan.FromMinutes(30)
        };

        // Assert
        options.AuthorizationCodeLifetime.Should().Be(TimeSpan.FromMinutes(3));
        options.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(30));
        options.RefreshTokenLifetime.Should().Be(TimeSpan.FromDays(7));
        options.IdTokenLifetime.Should().Be(TimeSpan.FromMinutes(30));
    }
}
