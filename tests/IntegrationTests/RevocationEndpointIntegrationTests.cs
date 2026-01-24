using System.Net;
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

public class RevocationEndpointIntegrationTests
{
    [Fact]
    public async Task Revoke_ValidAccessToken_Returns200OK()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "valid-access-token-12345",
            ["token_type_hint"] = "access_token",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().BeEmpty(); // RFC 7009 §2.2: response body should be empty
    }

    [Fact]
    public async Task Revoke_ValidRefreshToken_Returns200OK()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "valid-refresh-token-67890",
            ["token_type_hint"] = "refresh_token",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoke_InvalidToken_Returns200OK()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "non-existent-token",
            ["token_type_hint"] = "access_token",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        // RFC 7009 §2.2: Even if token doesn't exist, return 200 OK to prevent token scanning
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoke_MissingToken_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_request");
        body.Should().Contain("token parameter is required");
    }

    [Fact]
    public async Task Revoke_InvalidClientCredentials_Returns401()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "some-token",
            ["client_id"] = "test-client",
            ["client_secret"] = "wrong-secret"
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_client");
    }

    [Fact]
    public async Task Revoke_MissingClientCredentials_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "some-token"
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("client_id and client_secret are required");
    }

    [Fact]
    public async Task Revoke_GetMethod_Returns405()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/revoke?token=test&client_id=test-client&client_secret=test-secret");

        // RFC 7009 §2.1: Revocation endpoint requires POST method
        // ASP.NET Core routing automatically rejects non-POST with 405
        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    [Fact]
    public async Task Revoke_WithoutTokenTypeHint_Returns200OK()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var formData = new Dictionary<String, String>
        {
            ["token"] = "some-token",
            ["client_id"] = "test-client",
            ["client_secret"] = "test-secret"
            // No token_type_hint - should try both stores
        };

        var response = await client.PostAsync("/connect/revoke", new FormUrlEncodedContent(formData));

        // Should succeed without hint
        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Revoke_InvalidContentType_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var jsonContent = new StringContent("{\"token\":\"test\"}", System.Text.Encoding.UTF8, "application/json");
        var response = await client.PostAsync("/connect/revoke", jsonContent);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("application/x-www-form-urlencoded");
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
                        
                        // Seed a test client for authentication
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
}
