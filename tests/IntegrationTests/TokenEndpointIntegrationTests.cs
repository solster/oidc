using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
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

public class TokenEndpointIntegrationTests
{
    [Fact]
    public async Task Token_WithoutMethod_ReturnsMethodNotAllowed()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var response = await client.GetAsync("/connect/token");

        response.StatusCode.Should().Be(HttpStatusCode.MethodNotAllowed);
    }

    [Fact]
    public async Task Token_MissingGrantType_ReturnsBadRequest()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>());
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("grant_type");
    }

    [Fact]
    public async Task Token_UnsupportedGrantType_ReturnsError()
    {
        using var host = await CreateTestHost();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "password",
            ["username"] = "user",
            ["password"] = "pass"
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("unsupported_grant_type");
    }

    [Fact]
    public async Task Token_InvalidCode_ReturnsInvalidGrant()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "test_secret" }
            }
        });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "invalid_code",
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret"
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_grant");
    }

    [Fact]
    public async Task Token_ClientSecretBasic_Success()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var codeStore = host.Services.GetRequiredService<IAuthorizationCodeStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "test_secret" }
            }
        });

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var authCode = new AuthorizationCode
        {
            Code = GenerateAuthorizationCode(),
            ClientId = "test-client",
            UserId = "user123",
            RedirectUri = "https://client.test/callback",
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256",
            RequestedScopes = new List<String> { "openid", "profile" },
            Nonce = "test-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            CreatedAt = DateTimeOffset.UtcNow,
            IsConsumed = false
        };
        await codeStore.CreateCodeAsync(authCode);

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test_secret"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["code_verifier"] = codeVerifier
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<JsonElement>(body);
        
        tokenResponse.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        tokenResponse.GetProperty("id_token").GetString().Should().NotBeNullOrEmpty();
        tokenResponse.GetProperty("token_type").GetString().Should().Be("Bearer");
        tokenResponse.GetProperty("expires_in").GetInt32().Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Token_ClientSecretPost_Success()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var codeStore = host.Services.GetRequiredService<IAuthorizationCodeStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "test_secret" }
            }
        });

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var authCode = new AuthorizationCode
        {
            Code = GenerateAuthorizationCode(),
            ClientId = "test-client",
            UserId = "user123",
            RedirectUri = "https://client.test/callback",
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256",
            RequestedScopes = new List<String> { "openid", "profile" },
            Nonce = "test-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            CreatedAt = DateTimeOffset.UtcNow,
            IsConsumed = false
        };
        await codeStore.CreateCodeAsync(authCode);

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = codeVerifier
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<JsonElement>(body);
        
        tokenResponse.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        tokenResponse.GetProperty("id_token").GetString().Should().NotBeNullOrEmpty();
        tokenResponse.GetProperty("token_type").GetString().Should().Be("Bearer");
    }

    [Fact]
    public async Task Token_PublicClient_Success()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var codeStore = host.Services.GetRequiredService<IAuthorizationCodeStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "public-client",
            ClientName = "Public Client",
            ClientType = ClientType.Public,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        });

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var authCode = new AuthorizationCode
        {
            Code = GenerateAuthorizationCode(),
            ClientId = "public-client",
            UserId = "user123",
            RedirectUri = "https://client.test/callback",
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256",
            RequestedScopes = new List<String> { "openid", "profile" },
            Nonce = "test-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            CreatedAt = DateTimeOffset.UtcNow,
            IsConsumed = false
        };
        await codeStore.CreateCodeAsync(authCode);

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "public-client",
            ["code_verifier"] = codeVerifier
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Token_ExpiredCode_ReturnsInvalidGrant()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var codeStore = host.Services.GetRequiredService<IAuthorizationCodeStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "test_secret" }
            }
        });

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var authCode = new AuthorizationCode
        {
            Code = GenerateAuthorizationCode(),
            ClientId = "test-client",
            UserId = "user123",
            RedirectUri = "https://client.test/callback",
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256",
            RequestedScopes = new List<String> { "openid", "profile" },
            Nonce = "test-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-10),
            IsConsumed = false
        };
        await codeStore.CreateCodeAsync(authCode);

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = codeVerifier
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_grant");
        body.Should().Contain("expired");
    }

    [Fact]
    public async Task Token_InvalidPkce_ReturnsInvalidGrant()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var codeStore = host.Services.GetRequiredService<IAuthorizationCodeStore>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "test_secret" }
            }
        });

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var authCode = new AuthorizationCode
        {
            Code = GenerateAuthorizationCode(),
            ClientId = "test-client",
            UserId = "user123",
            RedirectUri = "https://client.test/callback",
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = "S256",
            RequestedScopes = new List<String> { "openid", "profile" },
            Nonce = "test-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            CreatedAt = DateTimeOffset.UtcNow,
            IsConsumed = false
        };
        await codeStore.CreateCodeAsync(authCode);

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var content = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = GenerateCodeVerifier()
        });
        var response = await client.PostAsync("/connect/token", content);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("invalid_grant");
        body.Should().Contain("code_verifier");
    }

    [Fact]
    public async Task CompleteAuthorizationCodeFlow_Success()
    {
        using var host = await CreateTestHost();
        var clientStore = host.Services.GetRequiredService<IClientStore>();
        var authenticator = (InMemoryResourceOwnerAuthenticator)host.Services.GetRequiredService<IResourceOwnerAuthenticator>();
        var consentService = host.Services.GetRequiredService<IConsentService>();

        await clientStore.CreateAsync(new OAuthClient
        {
            ClientId = "test-client",
            ClientName = "Test Client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile", "email" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "test_secret" }
            }
        });

        authenticator.SetCurrentUser(new UserPrincipal
        {
            Subject = "user123",
            Email = "user@test.com",
            Name = "Test User"
        });

        await consentService.GrantConsentAsync("user123", "test-client", new[] { "openid", "profile", "email" });

        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://issuer.test");

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);

        var authorizeResponse = await client.GetAsync($"/connect/authorize?response_type=code&client_id=test-client&redirect_uri=https://client.test/callback&scope=openid%20profile%20email&nonce=test-nonce&state=test-state&code_challenge={codeChallenge}&code_challenge_method=S256");

        authorizeResponse.StatusCode.Should().Be(HttpStatusCode.Redirect);
        var location = authorizeResponse.Headers.Location?.ToString();
        location.Should().NotBeNull();
        location.Should().Contain("code=");
        
        var uri = new Uri(location);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var code = query["code"];
        code.Should().NotBeNullOrEmpty();

        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test_secret"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credentials);

        var tokenContent = new FormUrlEncodedContent(new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = "https://client.test/callback",
            ["code_verifier"] = codeVerifier
        });
        var tokenResponse = await client.PostAsync("/connect/token", tokenContent);

        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await tokenResponse.Content.ReadAsStringAsync();
        var tokens = JsonSerializer.Deserialize<JsonElement>(body);
        
        tokens.GetProperty("access_token").GetString().Should().NotBeNullOrEmpty();
        tokens.GetProperty("id_token").GetString().Should().NotBeNullOrEmpty();
        tokens.GetProperty("token_type").GetString().Should().Be("Bearer");
        tokens.GetProperty("expires_in").GetInt32().Should().BeGreaterThan(0);
        tokens.GetProperty("scope").GetString().Should().Contain("openid");
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

                    services.AddSingleton<IClientStore, InMemoryClientStore>();
                    services.AddSingleton<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
                    services.AddSingleton<IResourceOwnerAuthenticator, InMemoryResourceOwnerAuthenticator>();
                    services.AddSingleton<IConsentService, InMemoryConsentService>();
                    services.AddSingleton<ITokenIssuer, InMemoryTokenIssuer>();
                    services.AddSingleton<ITokenClaimsProvider, InMemoryTokenClaimsProvider>();
                    services.AddSingleton<IAccessTokenStore, InMemoryAccessTokenStore>();
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

    private static String GenerateCodeVerifier()
    {
        var bytes = new Byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    private static String GenerateCodeChallenge(String verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    private static String GenerateAuthorizationCode()
    {
        var bytes = new Byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
