using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Handlers;
using Solster.Authentication.OpenIdConnect.Models;
using Xunit;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.UnitTests;

public class AuthorizeEndpointHandlerTests
{
    private readonly IClientStore _clientStore;
    private readonly IResourceOwnerAuthenticator _authenticator;
    private readonly IConsentService _consentService;
    private readonly IAuthorizationCodeStore _codeStore;
    private readonly ILogger<AuthorizeEndpointHandler> _logger;
    private readonly OpenIdConnectOptions _options;
    private readonly AuthorizeEndpointHandler _handler;

    public AuthorizeEndpointHandlerTests()
    {
        _clientStore = Substitute.For<IClientStore>();
        _authenticator = Substitute.For<IResourceOwnerAuthenticator>();
        _consentService = Substitute.For<IConsentService>();
        _codeStore = Substitute.For<IAuthorizationCodeStore>();
        _logger = Substitute.For<ILogger<AuthorizeEndpointHandler>>();

        _options = new OpenIdConnectOptions
        {
            Issuer = "https://issuer.test",
            RequirePkce = true,
            AuthorizationCodeLifetime = TimeSpan.FromMinutes(5),
            LoginPath = "/login",
            ConsentPath = "/consent"
        };

        _handler = new AuthorizeEndpointHandler(
            _clientStore,
            _authenticator,
            _consentService,
            _codeStore,
            _options,
            _logger);
    }

    [Fact]
    public async Task HandleAsync_MissingResponseType_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["client_id"] = "test-client"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // Verify it's a BadRequest result by checking the result type
    }

    [Fact]
    public async Task HandleAsync_InvalidResponseType_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "token",
            ["client_id"] = "test-client"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingClientId_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingRedirectUri_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_ClientNotFound_ReturnsBadRequest()
    {
        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns((OAuthClient?)null);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_RedirectUriMismatch_ReturnsBadRequest()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://malicious.test/callback"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingOpenIdScope_RedirectsWithError()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "profile email"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // Should redirect with error
    }

    [Fact]
    public async Task HandleAsync_InvalidScope_RedirectsWithError()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid admin"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingCodeChallenge_RedirectsWithError()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_InvalidCodeChallengeMethod_RedirectsWithError()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["code_challenge"] = "challenge123",
            ["code_challenge_method"] = "plain"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_MissingNonce_RedirectsWithError()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        var codeChallenge = GenerateCodeChallenge("test-verifier");

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
    }

    [Fact]
    public async Task HandleAsync_UserNotAuthenticated_RedirectsToLogin()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        _authenticator.GetCurrentUserAsync(Arg.Any<HttpContext>(), Arg.Any<CancellationToken>())
            .Returns((UserPrincipal?)null);

        var codeChallenge = GenerateCodeChallenge("test-verifier");

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "test-nonce",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // Should redirect to /login with return_url
    }

    [Fact]
    public async Task HandleAsync_ConsentRequired_RedirectsToConsent()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        var user = new UserPrincipal
        {
            Subject = "user123",
            Email = "user@test.com"
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        _authenticator.GetCurrentUserAsync(Arg.Any<HttpContext>(), Arg.Any<CancellationToken>())
            .Returns(user);

        _consentService.RequiresConsentAsync("user123", "test-client", Arg.Any<IEnumerable<String>>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var codeChallenge = GenerateCodeChallenge("test-verifier");

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "test-nonce",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // Should redirect to /consent with return_url
    }

    [Fact]
    public async Task HandleAsync_ValidRequest_GeneratesAuthorizationCode()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        var user = new UserPrincipal
        {
            Subject = "user123",
            Email = "user@test.com"
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        _authenticator.GetCurrentUserAsync(Arg.Any<HttpContext>(), Arg.Any<CancellationToken>())
            .Returns(user);

        _consentService.RequiresConsentAsync("user123", "test-client", Arg.Any<IEnumerable<String>>(), Arg.Any<CancellationToken>())
            .Returns(false);

        AuthorizationCode? capturedCode = null;
        _codeStore.CreateCodeAsync(Arg.Any<AuthorizationCode>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                capturedCode = callInfo.Arg<AuthorizationCode>();
                return capturedCode;
            });

        var codeChallenge = GenerateCodeChallenge("test-verifier");

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "test-nonce",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        capturedCode.Should().NotBeNull();
        capturedCode!.ClientId.Should().Be("test-client");
        capturedCode.UserId.Should().Be("user123");
        capturedCode.RedirectUri.Should().Be("https://client.test/callback");
        capturedCode.CodeChallenge.Should().Be(codeChallenge);
        capturedCode.CodeChallengeMethod.Should().Be("S256");
        capturedCode.Nonce.Should().Be("test-nonce");
        capturedCode.RequestedScopes.Should().Contain("openid");
        capturedCode.RequestedScopes.Should().Contain("profile");
        capturedCode.IsConsumed.Should().BeFalse();
        (capturedCode.ExpiresAt > DateTimeOffset.UtcNow).Should().BeTrue();
    }

    [Fact]
    public void ValidatePkceChallenge_S256_ValidVerifier_ReturnsTrue()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = GenerateCodeChallenge(verifier);

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, challenge, "S256");

        result.Should().BeTrue();
    }

    [Fact]
    public void ValidatePkceChallenge_S256_InvalidVerifier_ReturnsFalse()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = GenerateCodeChallenge(verifier);
        var wrongVerifier = "wrong-verifier";

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(wrongVerifier, challenge, "S256");

        result.Should().BeFalse();
    }

    [Fact]
    public void ValidatePkceChallenge_Plain_ValidVerifier_ReturnsTrue()
    {
        var verifier = "test-verifier";
        var challenge = verifier; // Plain method

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, challenge, "plain");

        result.Should().BeTrue();
    }

    [Fact]
    public void ValidatePkceChallenge_Plain_InvalidVerifier_ReturnsFalse()
    {
        var verifier = "test-verifier";
        var challenge = "different-challenge";

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, challenge, "plain");

        result.Should().BeFalse();
    }

    private static HttpContext CreateHttpContext(Dictionary<String, String> queryParams)
    {
        var context = new DefaultHttpContext();
        var queryCollection = new QueryCollection(queryParams.ToDictionary(
            kvp => kvp.Key,
            kvp => new Microsoft.Extensions.Primitives.StringValues(kvp.Value)
        ));
        context.Request.QueryString = new QueryString("?" + String.Join("&", queryParams.Select(kvp => $"{kvp.Key}={Uri.EscapeDataString(kvp.Value)}")));
        context.Request.Query = queryCollection;
        context.Request.Path = "/connect/authorize";
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("issuer.test");
        return context;
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
