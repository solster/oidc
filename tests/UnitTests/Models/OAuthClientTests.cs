using Solster.Authentication.OpenIdConnect.Models;
using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests.Models;

public class OAuthClientTests
{
    [Fact]
    public void OAuthClient_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var client = new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client"
        };

        // Assert
        client.Id.Should().NotBe(Guid.Empty);
        client.ClientId.Should().Be("test-client");
        client.ClientName.Should().Be("Test Client");
        client.ClientType.Should().Be(ClientType.Public);
        client.RedirectUris.Should().BeEmpty();
        client.AllowedScopes.Should().BeEmpty();
        client.IsDynamic.Should().BeFalse();
        client.RegistrationAccessToken.Should().BeNull();
        client.Secrets.Should().BeEmpty();
        (client.CreatedAt <= DateTimeOffset.UtcNow).Should().BeTrue();
        (client.UpdatedAt <= DateTimeOffset.UtcNow).Should().BeTrue();
    }

    [Fact]
    public void OAuthClient_ConfidentialClientType_CanBeSet()
    {
        // Arrange & Act
        var client = new OAuthClient
        {
            ClientId = "confidential-client",
            ClientName = "Confidential Client",
            ClientType = ClientType.Confidential
        };

        // Assert
        client.ClientType.Should().Be(ClientType.Confidential);
    }

    [Fact]
    public void OAuthClient_RedirectUrisAndScopes_CanBeAdded()
    {
        // Arrange & Act
        var client = new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = ["https://example.com/callback", "https://example.com/callback2"],
            AllowedScopes = ["openid", "profile", "email"]
        };

        // Assert
        client.RedirectUris.Count.Should().Be(2);
        client.RedirectUris.Should().Contain("https://example.com/callback");
        client.AllowedScopes.Count.Should().Be(3);
        client.AllowedScopes.Should().Contain("openid");
    }

    [Fact]
    public void OAuthClient_DynamicRegistration_CanBeConfigured()
    {
        // Arrange & Act
        var client = new OAuthClient
        {
            ClientId = "dynamic-client",
            ClientName = "Dynamic Client",
            IsDynamic = true,
            RegistrationAccessToken = "test-token"
        };

        // Assert
        client.IsDynamic.Should().BeTrue();
        client.RegistrationAccessToken.Should().Be("test-token");
    }
}
