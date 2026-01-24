using Solster.Authentication.OpenIdConnect.Models;
using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests.Models;

public class AuthorizationCodeTests
{
    [Fact]
    public void AuthorizationCode_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var code = new AuthorizationCode
        {
            Code = "test-code",
            ClientId = "test-client",
            UserId = "user-123",
            RedirectUri = "https://example.com/callback",
            CodeChallenge = "challenge",
            CodeChallengeMethod = "S256",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        // Assert
        code.Code.Should().Be("test-code");
        code.ClientId.Should().Be("test-client");
        code.UserId.Should().Be("user-123");
        code.RedirectUri.Should().Be("https://example.com/callback");
        code.CodeChallenge.Should().Be("challenge");
        code.CodeChallengeMethod.Should().Be("S256");
        code.IsConsumed.Should().BeFalse();
        code.ConsumedAt.Should().BeNull();
        code.RequestedScopes.Should().BeEmpty();
        (code.CreatedAt <= DateTimeOffset.UtcNow).Should().BeTrue();
    }

    [Fact]
    public void AuthorizationCode_WithNonceAndScopes_CanBeSet()
    {
        // Arrange & Act
        var code = new AuthorizationCode
        {
            Code = "test-code",
            ClientId = "test-client",
            UserId = "user-123",
            RedirectUri = "https://example.com/callback",
            CodeChallenge = "challenge",
            CodeChallengeMethod = "S256",
            Nonce = "test-nonce",
            RequestedScopes = ["openid", "profile"],
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        // Assert
        code.Nonce.Should().Be("test-nonce");
        code.RequestedScopes.Count.Should().Be(2);
        code.RequestedScopes.Should().Contain("openid");
    }

    [Fact]
    public void AuthorizationCode_ConsumedState_CanBeTracked()
    {
        // Arrange
        var code = new AuthorizationCode
        {
            Code = "test-code",
            ClientId = "test-client",
            UserId = "user-123",
            RedirectUri = "https://example.com/callback",
            CodeChallenge = "challenge",
            CodeChallengeMethod = "S256",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5)
        };

        // Act
        code.IsConsumed = true;
        code.ConsumedAt = DateTimeOffset.UtcNow;

        // Assert
        code.IsConsumed.Should().BeTrue();
        code.ConsumedAt.Should().NotBeNull();
    }
}
