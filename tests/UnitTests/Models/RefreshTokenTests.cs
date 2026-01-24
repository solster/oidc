using Solster.Authentication.OpenIdConnect.Models;
using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests.Models;

public class RefreshTokenTests
{
    [Fact]
    public void RefreshToken_DefaultValues_AreSetCorrectly()
    {
        // Arrange & Act
        var token = new RefreshToken
        {
            TokenHash = "hash-value",
            ClientId = "test-client",
            UserId = "user-123",
            TokenFamily = Guid.NewGuid(),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Assert
        token.TokenHash.Should().Be("hash-value");
        token.ClientId.Should().Be("test-client");
        token.UserId.Should().Be("user-123");
        token.TokenFamily.Should().NotBe(Guid.Empty);
        token.ParentTokenHash.Should().BeNull();
        token.ConsumedAt.Should().BeNull();
        token.RevokedAt.Should().BeNull();
        token.RevokedReason.Should().BeNull();
        token.Scopes.Should().BeEmpty();
        (token.CreatedAt <= DateTimeOffset.UtcNow).Should().BeTrue();
    }

    [Fact]
    public void RefreshToken_WithRotation_TracksParent()
    {
        // Arrange
        var originalToken = new RefreshToken
        {
            TokenHash = "original-hash",
            ClientId = "test-client",
            UserId = "user-123",
            TokenFamily = Guid.NewGuid(),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Act - Create rotated token
        var rotatedToken = new RefreshToken
        {
            TokenHash = "rotated-hash",
            ClientId = originalToken.ClientId,
            UserId = originalToken.UserId,
            TokenFamily = originalToken.TokenFamily,
            ParentTokenHash = originalToken.TokenHash,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Assert
        rotatedToken.ParentTokenHash.Should().Be(originalToken.TokenHash);
        rotatedToken.TokenFamily.Should().Be(originalToken.TokenFamily);
    }

    [Fact]
    public void RefreshToken_Revocation_CanBeTracked()
    {
        // Arrange
        var token = new RefreshToken
        {
            TokenHash = "hash-value",
            ClientId = "test-client",
            UserId = "user-123",
            TokenFamily = Guid.NewGuid(),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Act
        token.RevokedAt = DateTimeOffset.UtcNow;
        token.RevokedReason = "User logout";

        // Assert
        token.RevokedAt.Should().NotBeNull();
        token.RevokedReason.Should().Be("User logout");
    }

    [Fact]
    public void RefreshToken_WithScopes_CanBeSet()
    {
        // Arrange & Act
        var token = new RefreshToken
        {
            TokenHash = "hash-value",
            ClientId = "test-client",
            UserId = "user-123",
            TokenFamily = Guid.NewGuid(),
            Scopes = ["openid", "profile", "email"],
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(30)
        };

        // Assert
        token.Scopes.Count.Should().Be(3);
        token.Scopes.Should().Contain("openid");
    }
}
