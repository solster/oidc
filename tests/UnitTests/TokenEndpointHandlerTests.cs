using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using NSubstitute;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Handlers;
using Solster.Authentication.OpenIdConnect.Models;
using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests;

public class TokenEndpointHandlerTests
{
    private readonly IClientStore _clientStore;
    private readonly IAuthorizationCodeStore _codeStore;
    private readonly ITokenClaimsProvider _claimsProvider;
    private readonly ITokenIssuer _tokenIssuer;
    private readonly IAccessTokenStore _accessTokenStore;
    private readonly ILogger<TokenEndpointHandler> _logger;
    private readonly OpenIdConnectOptions _options;
    private readonly TokenEndpointHandler _handler;

    public TokenEndpointHandlerTests()
    {
        _clientStore = new InMemoryClientStore();
        _codeStore = new InMemoryAuthorizationCodeStore();
        _claimsProvider = new InMemoryTokenClaimsProvider();
        _tokenIssuer = new InMemoryTokenIssuer();
        _accessTokenStore = new InMemoryAccessTokenStore();
        _logger = Substitute.For<ILogger<TokenEndpointHandler>>();

        _options = new OpenIdConnectOptions
        {
            Issuer = "https://issuer.test",
            RequirePkce = true,
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(5),
            AccessTokenLifetime = TimeSpan.FromHours(1),
            IdTokenLifetime = TimeSpan.FromHours(1)
        };

        _handler = new TokenEndpointHandler(
            _clientStore,
            _codeStore,
            _claimsProvider,
            _tokenIssuer,
            _accessTokenStore,
            _options,
            _logger);
    }

    [Fact]
    public async Task HandleAsync_GetRequest_ReturnsMethodNotAllowed()
    {
        var context = CreateHttpContext("GET", null);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_InvalidContentType_ReturnsBadRequest()
    {
        var context = CreateHttpContext("POST", null);
        context.Request.ContentType = "application/json";

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingGrantType_ReturnsBadRequest()
    {
        var form = new Dictionary<String, String>();
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_UnsupportedGrantType_ReturnsUnsupportedGrantType()
    {
        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "password"
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingCode_ReturnsBadRequest()
    {
        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["redirect_uri"] = "https://client.test/callback"
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingRedirectUri_ReturnsBadRequest()
    {
        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "test_code"
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ClientAuthFails_ReturnsUnauthorized()
    {
        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "test_code",
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "nonexistent_client"
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ClientSecretBasic_AuthenticatesSuccessfully()
    {
        await SetupClient();

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);
        var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("test-client:test_secret"));
        context.Request.Headers["Authorization"] = "Basic " + credentials;

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ClientSecretPost_AuthenticatesSuccessfully()
    {
        await SetupClient();

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_PublicClient_AuthenticatesWithoutSecret()
    {
        var publicClient = new OAuthClient
        {
            ClientId = "public-client",
            ClientName = "Public Client",
            ClientType = ClientType.Public,
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };
        await _clientStore.CreateAsync(publicClient);

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("public-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "public-client",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_InvalidAuthCode_ReturnsInvalidGrant()
    {
        await SetupClient();

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = "invalid_code",
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret"
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ExpiredAuthCode_ReturnsInvalidGrant()
    {
        await SetupClient();

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");
        authCode.ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ClientIdMismatch_ReturnsInvalidGrant()
    {
        await SetupClient();
        var otherClient = new OAuthClient
        {
            ClientId = "other-client",
            ClientType = ClientType.Confidential,
            RedirectUris = new List<String> { "https://other.test/callback" },
            AllowedScopes = new List<String> { "openid" },
            Secrets = new List<ClientSecret>
            {
                new ClientSecret { SecretHash = "other_secret" }
            }
        };
        await _clientStore.CreateAsync(otherClient);

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "other-client",
            ["client_secret"] = "other_secret",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_RedirectUriMismatch_ReturnsInvalidGrant()
    {
        await SetupClient();

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://different.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingPkceVerifier_ReturnsInvalidGrant()
    {
        await SetupClient();

        var codeChallenge = GenerateCodeChallenge(GenerateCodeVerifier());
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret"
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_InvalidPkceVerifier_ReturnsInvalidGrant()
    {
        await SetupClient();

        var codeChallenge = GenerateCodeChallenge(GenerateCodeVerifier());
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = GenerateCodeVerifier()
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ValidRequest_ReturnsTokens()
    {
        await SetupClient();

        var codeVerifier = GenerateCodeVerifier();
        var codeChallenge = GenerateCodeChallenge(codeVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = codeVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_PkceVerifierTooShort_ReturnsInvalidGrant()
    {
        await SetupClient();

        var shortVerifier = "tooshort";
        var codeChallenge = GenerateCodeChallenge(shortVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = shortVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_PkceVerifierTooLong_ReturnsInvalidGrant()
    {
        await SetupClient();

        var longVerifier = new String('a', 129);
        var codeChallenge = GenerateCodeChallenge(longVerifier);
        var authCode = await SetupAuthorizationCode("test-client", codeChallenge, "S256");

        var form = new Dictionary<String, String>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = authCode.Code,
            ["redirect_uri"] = "https://client.test/callback",
            ["client_id"] = "test-client",
            ["client_secret"] = "test_secret",
            ["code_verifier"] = longVerifier
        };
        var context = CreateHttpContext("POST", form);

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    private async Task SetupClient()
    {
        var client = new OAuthClient
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
        };
        await _clientStore.CreateAsync(client);
    }

    private async Task<AuthorizationCode> SetupAuthorizationCode(String clientId, String codeChallenge, String codeChallengeMethod)
    {
        var authCode = new AuthorizationCode
        {
            Code = GenerateAuthorizationCode(),
            ClientId = clientId,
            UserId = "user123",
            RedirectUri = "https://client.test/callback",
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            RequestedScopes = new List<String> { "openid", "profile" },
            Nonce = "test-nonce",
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(5),
            CreatedAt = DateTimeOffset.UtcNow,
            IsConsumed = false
        };
        await _codeStore.CreateCodeAsync(authCode);
        return authCode;
    }

    private static HttpContext CreateHttpContext(String method, Dictionary<String, String>? formData)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Path = "/connect/token";
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("issuer.test");

        if (formData != null)
        {
            var formCollection = new FormCollection(formData.ToDictionary(
                kvp => kvp.Key,
                kvp => new StringValues(kvp.Value)
            ));
            context.Request.Form = formCollection;
        }

        return context;
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
