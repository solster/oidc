using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using AwesomeAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Xunit;

namespace Solster.Authentication.OpenIdConnect.IntegrationTests;

public class UserInfoEndpointIntegrationTests
{
    [Fact]
    public async Task UserInfo_MissingAuthorizationHeader_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        
        // RFC 6750 §3.1: WWW-Authenticate header MUST be present
        response.Headers.WwwAuthenticate.Should().NotBeEmpty();
        var wwwAuth = response.Headers.WwwAuthenticate.First().ToString();
        wwwAuth.Should().Contain("Bearer");
        wwwAuth.Should().Contain("invalid_token");
        
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_token");
        body.Should().Contain("Missing Authorization header");
    }

    [Fact]
    public async Task UserInfo_InvalidAuthorizationScheme_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", "credentials");
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        
        // RFC 6750 §3.1: WWW-Authenticate header MUST be present
        response.Headers.WwwAuthenticate.Should().NotBeEmpty();
        var wwwAuth = response.Headers.WwwAuthenticate.First().ToString();
        wwwAuth.Should().Contain("Bearer");
        wwwAuth.Should().Contain("invalid_token");
        
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("Bearer scheme");
    }

    [Fact]
    public async Task UserInfo_EmptyToken_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "");
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task UserInfo_InvalidToken_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "invalid.token.here");
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        
        // RFC 6750 §3.1: WWW-Authenticate header MUST be present
        response.Headers.WwwAuthenticate.Should().NotBeEmpty();
        
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_token");
    }

    [Fact]
    public async Task UserInfo_ExpiredToken_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var expiredToken = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore,
            expiresIn: TimeSpan.FromMinutes(-10) // Expired 10 minutes ago
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", expiredToken);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_token");
    }

    [Fact]
    public async Task UserInfo_RevokedToken_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var tokenStore = host.Services.GetRequiredService<IAccessTokenStore>();
        
        var tokenId = Guid.NewGuid().ToString();
        var accessToken = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore,
            jti: tokenId
        );

        // Revoke the token
        await tokenStore.RevokeTokenAsync(tokenId);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("revoked");
    }

    [Fact]
    public async Task UserInfo_ValidToken_ReturnsUserClaims()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile", "email" },
            keyStore: keyStore
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.GetAsync("/connect/userinfo");


        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Content.Headers.ContentType?.MediaType.Should().Be("application/json");

        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        
        // Must contain 'sub' claim
        json.RootElement.GetProperty("sub").GetString().Should().Be("user123");
        
        // Should contain profile claims
        json.RootElement.GetProperty("name").GetString().Should().Be("Test User");
        json.RootElement.GetProperty("given_name").GetString().Should().Be("Test");
        json.RootElement.GetProperty("family_name").GetString().Should().Be("User");
        
        // Should contain email claims
        json.RootElement.GetProperty("email").GetString().Should().Be("test@example.com");
        json.RootElement.GetProperty("email_verified").GetString().Should().Be("true");
    }

    [Fact]
    public async Task UserInfo_TokenWithOnlyOpenIdScope_ReturnsOnlySub()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid" },
            keyStore: keyStore
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        
        // Should only contain 'sub' claim
        json.RootElement.GetProperty("sub").GetString().Should().Be("user123");
        
        // Should NOT contain profile or email claims
        json.RootElement.TryGetProperty("name", out _).Should().BeFalse();
        json.RootElement.TryGetProperty("email", out _).Should().BeFalse();
    }

    [Fact]
    public async Task UserInfo_TokenWithProfileScope_ReturnsProfileClaims()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        
        json.RootElement.GetProperty("sub").GetString().Should().Be("user123");
        json.RootElement.GetProperty("name").GetString().Should().Be("Test User");
        
        // Should NOT contain email claims
        json.RootElement.TryGetProperty("email", out _).Should().BeFalse();
    }

    [Fact]
    public async Task UserInfo_PostMethod_ReturnsUserClaims()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var response = await client.PostAsync("/connect/userinfo", new StringContent(""));

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        
        json.RootElement.GetProperty("sub").GetString().Should().Be("user123");
        json.RootElement.GetProperty("name").GetString().Should().Be("Test User");
    }

    [Fact]
    public async Task UserInfo_TokenMissingSubClaim_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        
        // Create token without 'sub' claim
        var token = CreateAccessToken(
            userId: null!, // No sub claim
            clientId: "test-client",
            scopes: new[] { "openid" },
            keyStore: keyStore,
            includeSub: false
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("missing subject");
    }

    [Fact]
    public async Task UserInfo_TokenMissingJtiClaim_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        
        // Create token without 'jti' claim
        var token = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore,
            jti: null, // No jti - should fail revocation check
            includeJti: false
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("missing token identifier");
    }

    [Fact]
    public async Task UserInfo_TokenWithWrongAudience_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        
        // Create token with wrong audience
        var token = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore,
            audience: "wrong-audience" // Wrong audience - should fail
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_token");
    }

    [Fact]
    public async Task UserInfo_TokenWithCorrectAudience_ReturnsUserClaims()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        
        // Create token with correct audience
        var token = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore,
            audience: "userinfo" // Correct audience
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        
        json.RootElement.GetProperty("sub").GetString().Should().Be("user123");
        json.RootElement.GetProperty("name").GetString().Should().Be("Test User");
    }

    [Fact]
    public async Task UserInfo_TokenWithoutAudience_ReturnsUnauthorized()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        
        // Create token without audience claim
        var token = CreateAccessToken(
            userId: "user123",
            clientId: "test-client",
            scopes: new[] { "openid", "profile" },
            keyStore: keyStore,
            audience: null // No audience - should fail when validation enabled
        );

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_token");
    }
    // Helper methods

    private static String CreateAccessToken(
        String userId,
        String clientId,
        String[] scopes,
        ISigningKeyStore keyStore,
        TimeSpan? expiresIn = null,
        String? jti = null,
        Boolean includeSub = true,
        Boolean includeJti = true,
        String? audience = "userinfo")
    {
        var claims = new List<Claim>();
        
        if (includeSub)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userId));
        }
        
        if (includeJti)
        {
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, jti ?? Guid.NewGuid().ToString()));
        }
        
        claims.Add(new Claim("client_id", clientId));
        claims.Add(new Claim("scope", String.Join(" ", scopes)));

        var expiration = DateTime.UtcNow.Add(expiresIn ?? TimeSpan.FromHours(1));
        var notBefore = expiration < DateTime.UtcNow ? expiration.AddMinutes(-5) : DateTime.UtcNow;

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = "https://issuer.test",
            Audience = audience, // Add audience for UserInfo endpoint validation
            NotBefore = notBefore,
            Expires = expiration,
            SigningCredentials = GetSigningCredentials(keyStore)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private static SigningCredentials GetSigningCredentials(ISigningKeyStore keyStore)
    {
        return keyStore.GetCurrentSigningCredentials();
    }

    private static async Task<IHost> CreateTestHost()
    {
        var host = await new HostBuilder()
            .ConfigureWebHost(webBuilder =>
            {
                webBuilder
                    .UseTestServer()
                    .ConfigureServices(services =>
                    {
                        services.AddRouting();
                        services.AddOpenIdConnect(options =>
                        {
                            options.Issuer = "https://issuer.test";
                            options.PublicOrigin = "https://issuer.test";
                        });

                        // Register in-memory implementations
                        services.AddSingleton<IClientStore, InMemoryClientStore>();
                        services.AddSingleton<IResourceOwnerAuthenticator, InMemoryResourceOwnerAuthenticator>();
                        services.AddSingleton<IConsentService, InMemoryConsentService>();
                        services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
                        services.AddSingleton<ITokenClaimsProvider, InMemoryTokenClaimsProvider>();
                        services.AddSingleton<ITokenIssuer, InMemoryTokenIssuer>();
                        services.AddSingleton<IAccessTokenStore, InMemoryAccessTokenStore>();
                        services.AddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
                    })
                    .Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapOpenIdConnect();
                        });
                    });
            })
            .StartAsync();

        return host;
    }
}
