using System.Net;
using System.Security.Cryptography;
using System.Text;
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

public class AuthorizeEndpointIntegrationTests
{
    [Fact]
    public async Task Authorize_MissingResponseType_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?client_id=test-client");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_InvalidResponseType_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?response_type=token&client_id=test-client");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_ClientNotFound_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=nonexistent&redirect_uri=https://client.test/callback");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_RedirectUriMismatch_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://malicious.test/callback");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_MissingOpenIdScope_RedirectsWithError()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=profile");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("error=invalid_scope");
        location.Should().Contain("https://client.test/callback");
    }

    [Fact]
    public async Task Authorize_MissingPkce_RedirectsWithError()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile&nonce=test-nonce&state=test-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("error=invalid_request");
        location.Should().Contain("code_challenge");
        location.Should().Contain("state=test-state");
    }

    [Fact]
    public async Task Authorize_UserNotAuthenticated_RedirectsToLogin()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var codeChallenge = GenerateCodeChallenge("test-verifier");
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile&nonce=test-nonce&state=test-state&code_challenge={codeChallenge}&code_challenge_method=S256");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("/login");
        location.Should().Contain("return_url");
    }

    [Fact]
    public async Task Authorize_ConsentRequired_RedirectsToConsent()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var authenticator = (InMemoryResourceOwnerAuthenticator)host.Services.GetRequiredService<IResourceOwnerAuthenticator>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        authenticator.SetCurrentUser(new UserPrincipal
        {
            Subject = "user123",
            Email = "user@test.com",
            Name = "Test User"
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var codeChallenge = GenerateCodeChallenge("test-verifier");
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile&nonce=test-nonce&state=test-state&code_challenge={codeChallenge}&code_challenge_method=S256");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("/connect/consent");
        location.Should().Contain("return_url");
    }

    [Fact]
    public async Task Authorize_ValidRequest_ReturnsAuthorizationCode()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var authenticator = (InMemoryResourceOwnerAuthenticator)host.Services.GetRequiredService<IResourceOwnerAuthenticator>();
        var consentService = host.Services.GetRequiredService<IConsentService>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        authenticator.SetCurrentUser(new UserPrincipal
        {
            Subject = "user123",
            Email = "user@test.com",
            Name = "Test User"
        });

        // Grant consent
        await consentService.GrantConsentAsync("user123", "test-client", new[] { "openid", "profile" });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var codeChallenge = GenerateCodeChallenge("test-verifier");
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile&nonce=test-nonce&state=test-state&code_challenge={codeChallenge}&code_challenge_method=S256");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("https://client.test/callback");
        location.Should().Contain("code=");
        location.Should().Contain("state=test-state");
        location.Should().NotContain("error");
    }

    [Fact]
    public async Task Authorize_StatePreserved_InErrorResponse()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=profile&state=my-custom-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("error=invalid_scope");
        location.Should().Contain("state=my-custom-state");
    }

    [Fact]
    public async Task Authorize_RedirectUriExactMatch_CaseSensitive()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // Try with different case - should now fail due to case-sensitive matching (RFC 6749 §3.1.2.2)
        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://CLIENT.TEST/callback");

        // Should return BadRequest for case mismatch (implementation uses Ordinal)
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_RedirectUriWithFragment_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // RFC 6749 §3.1.2: Fragment in redirect_uri must be rejected
        var response = await client.GetAsync("/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback%23fragment");

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Authorize_CodeChallengeTooShort_ReturnsError()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // RFC 7636 §4.3: code_challenge must be 43-128 characters
        var shortChallenge = "abcdefghijklmnopqrstuvwxyz0123456789ABC"; // 41 chars
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile&nonce=test-nonce&code_challenge={shortChallenge}&code_challenge_method=S256&state=test-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("error=invalid_request");
        location.Should().Contain("code_challenge");
    }

    [Fact]
    public async Task Authorize_CodeChallengeTooLong_ReturnsError()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        // RFC 7636 §4.3: code_challenge must be 43-128 characters
        var longChallenge = new String('a', 129);
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile&nonce=test-nonce&code_challenge={longChallenge}&code_challenge_method=S256&state=test-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("error=invalid_request");
    }

    [Fact]
    public async Task Authorize_EmptyScope_ReturnsError()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var codeChallenge = GenerateCodeChallenge("test-verifier");
        // RFC 6749 §3.3: Empty scope should be rejected
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=&nonce=test-nonce&code_challenge={codeChallenge}&code_challenge_method=S256&state=test-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("error=invalid_request");
        location.Should().Contain("scope");
    }

    [Fact]
    public async Task Authorize_DuplicateScopes_HandledCorrectly()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var authenticator = (InMemoryResourceOwnerAuthenticator)host.Services.GetRequiredService<IResourceOwnerAuthenticator>();
        var consentService = host.Services.GetRequiredService<IConsentService>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile", "email" }
        });

        authenticator.SetCurrentUser(new UserPrincipal
        {
            Subject = "user123",
            Email = "user@test.com",
            Name = "Test User"
        });

        // Grant consent
        await consentService.GrantConsentAsync("user123", "test-client", new[] { "openid", "profile", "email" });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var codeChallenge = GenerateCodeChallenge("test-verifier");
        // RFC 6749 §3.3: Duplicate scopes should be deduplicated
        var response = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile%20profile%20email%20openid&nonce=test-nonce&code_challenge={codeChallenge}&code_challenge_method=S256&state=test-state");

        response.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = response.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("code=");
        location.Should().NotContain("error");
    }

    private static async Task<IHost> CreateTestHost()
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();

                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();

                    services.AddOpenIdConnect("https://issuer.test", opts =>
                    {
                        opts.PublicOrigin = "https://issuer.test";
                        opts.RequirePkce = true;
                    });

                    // Register in-memory implementations
                    services.AddSingleton<IClientStore, InMemoryClientStore>();
                    services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
                    services.AddSingleton<IResourceOwnerAuthenticator, InMemoryResourceOwnerAuthenticator>();
                    services.AddSingleton<IConsentService, InMemoryConsentService>();
                });

                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapOpenIdConnect();
                    });
                });
            });

        return await hostBuilder.StartAsync();
    }

    private static String GenerateCodeChallenge(String verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
