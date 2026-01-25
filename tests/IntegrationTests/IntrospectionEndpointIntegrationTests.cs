using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using AwesomeAssertions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;
using Xunit;

namespace Solster.Authentication.OpenIdConnect.IntegrationTests;

public class IntrospectionEndpointIntegrationTests
{
    [Fact]
    public async Task Introspect_ValidAccessToken_ReturnsActiveTrue()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // Create a valid access token
        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken("user123", "test-client", ["openid", "profile"], keyStore);
        
        // Store token reference
        var tokenStore = host.Services.GetRequiredService<IAccessTokenStore>();
        await tokenStore.SaveTokenAsync(new AccessTokenReference
        {
            TokenId = ExtractJti(accessToken),
            UserId = "user123",
            ClientId = "test-client",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CreatedAt = DateTimeOffset.UtcNow
        });

        var formData = new Dictionary<String, String>
        {
            ["token"] = accessToken,
            ["token_type_hint"] = "access_token",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("active").GetBoolean().Should().BeTrue();
        json.RootElement.GetProperty("client_id").GetString().Should().Be("test-client");
        json.RootElement.GetProperty("sub").GetString().Should().Be("user123");
        json.RootElement.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [Fact]
    public async Task Introspect_ExpiredToken_ReturnsActiveFalse()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // Create an expired token
        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken("user123", "test-client", ["openid"], keyStore, TimeSpan.FromHours(-1));
        
        // Store token reference (expired)
        var tokenStore = host.Services.GetRequiredService<IAccessTokenStore>();
        await tokenStore.SaveTokenAsync(new AccessTokenReference
        {
            TokenId = ExtractJti(accessToken),
            UserId = "user123",
            ClientId = "test-client",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(-1), // Expired
            CreatedAt = DateTimeOffset.UtcNow.AddHours(-2)
        });

        var formData = new Dictionary<String, String>
        {
            ["token"] = accessToken,
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("active").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Introspect_RevokedToken_ReturnsActiveFalse()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken("user123", "test-client", ["openid"], keyStore);
        var jti = ExtractJti(accessToken);
        
        // Store and revoke token
        var tokenStore = host.Services.GetRequiredService<IAccessTokenStore>();
        await tokenStore.SaveTokenAsync(new AccessTokenReference
        {
            TokenId = jti,
            UserId = "user123",
            ClientId = "test-client",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CreatedAt = DateTimeOffset.UtcNow
        });
        await tokenStore.RevokeTokenAsync(jti);

        var formData = new Dictionary<String, String>
        {
            ["token"] = accessToken,
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("active").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Introspect_InvalidToken_ReturnsActiveFalse()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "invalid.token.here",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        // RFC 7662 §2.2: Return active=false for invalid tokens
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("active").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Introspect_MissingToken_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("token parameter is required");
    }

    [Fact]
    public async Task Introspect_InvalidClientCredentials_Returns401()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "some.token.here",
            ["client_id"] = "test-client",
            ["client_secret"] = "wrong-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_client");
    }

    [Fact]
    public async Task Introspect_GetMethod_Returns405()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/introspect?token=test&client_id=test-client&client_secret=test-secret");

        // RFC 7662 §2.1: POST method required
        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    [Fact]
    public async Task Introspect_TokenOwnedByDifferentClient_ReturnsActiveFalse()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // Create token owned by client-A
        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken("user123", "client-A", ["openid"], keyStore);
        
        var tokenStore = host.Services.GetRequiredService<IAccessTokenStore>();
        await tokenStore.SaveTokenAsync(new AccessTokenReference
        {
            TokenId = ExtractJti(accessToken),
            UserId = "user123",
            ClientId = "client-A", // Owned by client-A
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CreatedAt = DateTimeOffset.UtcNow
        });

        // client-B tries to introspect it
        var formData = new Dictionary<String, String>
        {
            ["token"] = accessToken,
            ["client_id"] = "test-client", // client-B
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        // RFC 7662 §2.2: Return active=false if client not authorized
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("active").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Introspect_WithTokenTypeHint_ReturnsCorrectly()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var accessToken = CreateAccessToken("user123", "test-client", ["openid"], keyStore);
        
        var tokenStore = host.Services.GetRequiredService<IAccessTokenStore>();
        await tokenStore.SaveTokenAsync(new AccessTokenReference
        {
            TokenId = ExtractJti(accessToken),
            UserId = "user123",
            ClientId = "test-client",
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
            CreatedAt = DateTimeOffset.UtcNow
        });

        var formData = new Dictionary<String, String>
        {
            ["token"] = accessToken,
            ["token_type_hint"] = "access_token", // Hint provided
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/introspect", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var json = JsonDocument.Parse(body);
        json.RootElement.GetProperty("active").GetBoolean().Should().BeTrue();
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
                        var clientStore = new InMemoryClientStore();
                        services.AddSingleton<IClientStore>(clientStore);
                        services.AddSingleton<IResourceOwnerAuthenticator, InMemoryResourceOwnerAuthenticator>();
                        services.AddSingleton<IConsentService, InMemoryConsentService>();
                        services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
                        services.AddSingleton<ITokenClaimsProvider, InMemoryTokenClaimsProvider>();
                        services.AddSingleton<ITokenIssuer, InMemoryTokenIssuer>();
                        services.AddSingleton<IAccessTokenStore, InMemoryAccessTokenStore>();
                        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
                        services.AddSingleton<ISigningKeyStore, InMemorySigningKeyStore>();
                        
                        // Seed test client
                        var testClient = new OAuthClient
                        {
                            ClientId = "test-client",
                            ClientName = "Test Client",
                            ClientType = ClientType.Confidential,
                            Secrets = new List<ClientSecret>
                            {
                                new ClientSecret { SecretHash = "test-secret" }
                            }
                        };
                        clientStore.CreateAsync(testClient).Wait();
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

    private static String CreateAccessToken(
        String userId,
        String clientId,
        String[] scopes,
        ISigningKeyStore keyStore,
        TimeSpan? expiresIn = null)
    {
        var signingCredentials = keyStore.GetCurrentSigningCredentials();
        
        var now = DateTime.UtcNow;
        var expiration = expiresIn ?? TimeSpan.FromHours(1);
        var expiresAt = now.Add(expiration);
        
        // Ensure notBefore is always before expires (handle negative expiresIn for expired tokens)
        var notBefore = expiration.TotalSeconds < 0 
            ? expiresAt.AddMinutes(-5)  // For expired tokens, set notBefore before expiration
            : now;
        
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(notBefore).ToUnixTimeSeconds().ToString()),
            new Claim("scope", String.Join(" ", scopes)),
            new Claim("client_id", clientId)
        };

        var token = new JwtSecurityToken(
            issuer: "https://issuer.test",
            audience: "https://issuer.test",
            claims: claims,
            notBefore: notBefore,
            expires: expiresAt,
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static String ExtractJti(String jwt)
    {
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(jwt);
        return token.Claims.First(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
    }
}
