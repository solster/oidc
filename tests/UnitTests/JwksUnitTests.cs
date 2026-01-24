using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests;

public class JwksUnitTests
{
    [Fact]
    public void Jwks_Contains_Public_Key_With_Kid_And_Alg()
    {
        using var store = new InMemorySigningKeyStore();
        var jwks = store.GetCurrentKeySet();
        jwks.Should().NotBeNull();
        jwks.Keys.Should().NotBeEmpty();
        var key = jwks.Keys[0];
        String.IsNullOrEmpty(key.Kid).Should().BeFalse();
        key.Use.Should().Be("sig");
        key.Alg.Should().Be("RS256");
        String.IsNullOrEmpty(key.N).Should().BeFalse();
        String.IsNullOrEmpty(key.E).Should().BeFalse();
    }
}