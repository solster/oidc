using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
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

public class EndSessionEndpointIntegrationTests
{
    [Fact]
    public async Task EndSession_WithValidIdTokenHintAndRedirectUri_RedirectsSuccessfully()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // Create a valid ID token
        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var idToken = CreateIdToken("user123", "test-client", keyStore);

        var response = await client.GetAsync(
            $"/connect/endsession?id_token_hint={idToken}" +
            $"&post_logout_redirect_uri={Uri.EscapeDataString("https://client.example.com/logged-out")}" +
            $"&state=test-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("https://client.example.com/logged-out");
        location.Should().Contain("state=test-state");
    }

    [Fact]
    public async Task EndSession_WithoutIdTokenHint_ReturnsLogoutConfirmation()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/endsession");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("Logged Out");
    }

    [Fact]
    public async Task EndSession_WithInvalidPostLogoutUri_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var idToken = CreateIdToken("user123", "test-client", keyStore);

        var response = await client.GetAsync(
            $"/connect/endsession?id_token_hint={idToken}" +
            $"&post_logout_redirect_uri={Uri.EscapeDataString("https://evil.com/phishing")}");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("not registered");
    }

    [Fact]
    public async Task EndSession_WithStateButNoRedirectUri_ReturnsLogoutConfirmation()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var idToken = CreateIdToken("user123", "test-client", keyStore);

        var response = await client.GetAsync(
            $"/connect/endsession?id_token_hint={idToken}&state=test-state");

        // Without redirect URI, state is ignored and confirmation page is shown
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("Logged Out");
    }

    [Fact]
    public async Task EndSession_GetMethod_Works()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/endsession");

        // GET method is supported per OIDC Session Management §5
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EndSession_PostMethod_Works()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.PostAsync("/connect/endsession", 
            new FormUrlEncodedContent(new Dictionary<String, String>()));

        // POST method is supported per OIDC Session Management §5
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EndSession_WithInvalidIdTokenHint_ContinuesWithLogout()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/endsession?id_token_hint=invalid.token.here");

        // OIDC Session Management §5: Continue with logout even if id_token_hint is invalid
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("Logged Out");
    }

    [Fact]
    public async Task EndSession_WithExpiredIdTokenHint_StillWorks()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // Create expired ID token (1 hour ago)
        var keyStore = host.Services.GetRequiredService<ISigningKeyStore>();
        var idToken = CreateIdToken("user123", "test-client", keyStore, TimeSpan.FromHours(-1));

        var response = await client.GetAsync(
            $"/connect/endsession?id_token_hint={idToken}" +
            $"&post_logout_redirect_uri={Uri.EscapeDataString("https://client.example.com/logged-out")}");

        // Logout should work even with expired ID token (we don't validate lifetime)
        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().Contain("https://client.example.com/logged-out");
    }

    [Fact]
    public async Task EndSession_WithPostLogoutUriWithoutIdTokenHint_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync(
            "/connect/endsession?post_logout_redirect_uri=" +
            Uri.EscapeDataString("https://client.example.com/logged-out"));

        // Cannot validate redirect URI without knowing which client
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("id_token_hint");
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
                        
                        // Seed test client with post-logout redirect URI
                        var testClient = new OAuthClient
                        {
                            ClientId = "test-client",
                            ClientName = "Test Client",
                            ClientType = ClientType.Confidential,
                            PostLogoutRedirectUris = new List<String>
                            {
                                "https://client.example.com/logged-out"
                            },
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

    private static String CreateIdToken(
        String userId,
        String clientId,
        ISigningKeyStore keyStore,
        TimeSpan? expiresIn = null)
    {
        var signingCredentials = keyStore.GetCurrentSigningCredentials();
        
        var now = DateTime.UtcNow;
        var expiration = expiresIn ?? TimeSpan.FromHours(1);
        var expiresAt = now.Add(expiration);
        
        // Ensure notBefore is always before expires
        var notBefore = expiration.TotalSeconds < 0 
            ? expiresAt.AddMinutes(-5)
            : now;
        
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim(JwtRegisteredClaimNames.Aud, clientId),
            new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(notBefore).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.AuthTime, new DateTimeOffset(notBefore).ToUnixTimeSeconds().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: "https://issuer.test",
            audience: clientId,
            claims: claims,
            notBefore: notBefore,
            expires: expiresAt,
            signingCredentials: signingCredentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
