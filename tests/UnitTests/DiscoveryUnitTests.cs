using Xunit;
using System.Text.Json;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests;

public class DiscoveryUnitTests
{
        [Fact]
        public void Discovery_Includes_Required_Fields_From_Options()
        {
            var options = new OpenIdConnectOptions
            {
            Issuer = "https://issuer.test",
            PublicOrigin = "https://example.test"
        };

        var discovery = new
        {
            issuer = options.Issuer,
            authorization_endpoint = options.PublicOrigin.TrimEnd('/') + options.AuthorizationPath,
            token_endpoint = options.PublicOrigin.TrimEnd('/') + options.TokenPath,
            userinfo_endpoint = options.PublicOrigin.TrimEnd('/') + options.UserInfoPath,
            jwks_uri = options.PublicOrigin.TrimEnd('/') + options.JwksPath,
            response_types_supported = options.SupportedResponseTypes,
            subject_types_supported = options.SupportedSubjectTypes,
            id_token_signing_alg_values_supported = options.SupportedIdTokenSigningAlgValues,
            scopes_supported = options.SupportedScopes,
            token_endpoint_auth_methods_supported = options.SupportedTokenEndpointAuthMethods
        };

        var json = JsonSerializer.Serialize(discovery);
        json.Should().Contain("issuer");
        json.Should().Contain("authorization_endpoint");
        json.Should().Contain("token_endpoint");
        json.Should().Contain("userinfo_endpoint");
        json.Should().Contain("jwks_uri");
        json.Should().Contain("response_types_supported");
    }
}