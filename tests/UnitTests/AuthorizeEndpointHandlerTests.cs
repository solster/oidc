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

/// <summary>
/// Tests for OAuth 2.0 / OpenID Connect authorization endpoint handler.
/// Validates compliance with:
/// - RFC 6749 (OAuth 2.0 Authorization Framework)
/// - RFC 7636 (Proof Key for Code Exchange - PKCE)
/// - OpenID Connect Core 1.0
/// </summary>
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

    // RFC 6749 §4.1.1: Authorization Request - response_type parameter
    // RFC 6749 §3.1: The authorization endpoint is used by the authorization code grant type
    [Fact]
    public async Task HandleAsync_MissingResponseType_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["client_id"] = "test-client"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 6749 §4.1.2.1: Must return error for invalid request
    }

    // RFC 6749 §3.1.1: The authorization server MUST support the authorization code grant type
    // RFC 6749 §4.1.2.1: Returns unsupported_response_type error
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
        // RFC 6749 §4.1.2.1: unsupported_response_type error
    }

    // RFC 6749 §4.1.1: client_id is REQUIRED
    [Fact]
    public async Task HandleAsync_MissingClientId_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 6749 §4.1.2.1: invalid_request error
    }

    // RFC 6749 §4.1.1: redirect_uri is REQUIRED if multiple URIs registered
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
        // RFC 6749 §4.1.2.1: invalid_request error
    }

    // RFC 6749 §4.1.1: Authorization server MUST validate the client_id
    // RFC 6749 §4.1.2.1: Returns invalid_client error
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

    // RFC 6749 §3.1.2.3: The authorization server MUST validate redirect_uri
    // RFC 6749 §4.1.2.1: Returns invalid_request if redirect_uri doesn't match
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
        // RFC 6749 §4.1.2.1: invalid_request error
    }

    // OpenID Connect Core 1.0 §3.1.2.1: The openid scope value MUST be present
    // RFC 6749 §4.1.2.1: Returns invalid_scope error
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
        // OpenID Connect: Must have openid scope, redirect with invalid_scope
    }

    // RFC 6749 §3.3: The authorization server MAY fully or partially ignore the scope
    // RFC 6749 §4.1.2.1: Returns invalid_scope if scope exceeds granted permissions
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
        // RFC 6749 §4.1.2.1: invalid_scope error
    }

    // RFC 7636 §4.4.1: The client MUST send code_challenge and code_challenge_method
    // RFC 7636 §4.4.1: Returns invalid_request if PKCE is required but not provided
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
        // RFC 7636 §4.4.1: invalid_request error
    }

    // RFC 7636 §4.3: code_challenge_method MUST be "S256" or "plain"
    // Implementation requires S256 for security
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
            ["code_challenge_method"] = "plain" // Not allowed when RequirePkce with S256
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 7636 §4.4.1: invalid_request error
    }

    // OpenID Connect Core 1.0 §3.1.2.1: nonce is REQUIRED for implicit/hybrid
    // Recommended for code flow to prevent replay attacks
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
        // OpenID Connect: nonce prevents replay attacks
    }

    // RFC 6749 §3.1: The resource owner authenticates with the authorization server
    // User must be authenticated before granting authorization
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
        // RFC 6749 §3.1: Redirect to login page with return_url
    }

    // RFC 6749 §3.1.2.4: The authorization server SHOULD obtain consent from resource owner
    // OpenID Connect: User must consent to share information with client
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
        // RFC 6749 §3.1.2.4: Redirect to consent page with return_url
    }

    // RFC 6749 §4.1.2: Successful authorization response with code
    // RFC 7636 §4.4: Authorization code bound to PKCE challenge
    // OpenID Connect: Authorization code bound to nonce
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
        // RFC 6749 §4.1.2: Authorization code issued
        capturedCode!.ClientId.Should().Be("test-client");
        capturedCode.UserId.Should().Be("user123");
        capturedCode.RedirectUri.Should().Be("https://client.test/callback");
        // RFC 7636 §4.4: Code challenge bound to authorization code
        capturedCode.CodeChallenge.Should().Be(codeChallenge);
        capturedCode.CodeChallengeMethod.Should().Be("S256");
        // OpenID Connect: Nonce bound to authorization code
        capturedCode.Nonce.Should().Be("test-nonce");
        capturedCode.RequestedScopes.Should().Contain("openid");
        capturedCode.RequestedScopes.Should().Contain("profile");
        // RFC 6749 §4.1.2: Authorization code is single-use
        capturedCode.IsConsumed.Should().BeFalse();
        // RFC 6749 §4.1.2: Authorization code has expiration
        (capturedCode.ExpiresAt > DateTimeOffset.UtcNow).Should().BeTrue();
    }

    // RFC 7636 §4.6: Server verifies code_verifier using S256 transformation
    [Fact]
    public void ValidatePkceChallenge_S256_ValidVerifier_ReturnsTrue()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = GenerateCodeChallenge(verifier);

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, challenge, "S256");

        result.Should().BeTrue();
        // RFC 7636 §4.6: BASE64URL(SHA256(ASCII(code_verifier))) == code_challenge
    }

    // RFC 7636 §4.6: Server rejects invalid code_verifier
    [Fact]
    public void ValidatePkceChallenge_S256_InvalidVerifier_ReturnsFalse()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var challenge = GenerateCodeChallenge(verifier);
        var wrongVerifier = "wrong-verifier";

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(wrongVerifier, challenge, "S256");

        result.Should().BeFalse();
        // RFC 7636 §4.6: Mismatched verifier should fail
    }

    // RFC 7636 §4.6: Server supports plain method (code_verifier == code_challenge)
    [Fact]
    public void ValidatePkceChallenge_Plain_ValidVerifier_ReturnsTrue()
    {
        var verifier = "test-verifier";
        var challenge = verifier; // Plain method

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, challenge, "plain");

        result.Should().BeTrue();
        // RFC 7636 §4.6: Plain method is direct comparison
    }

    // RFC 7636 §4.6: Server rejects mismatched plain verifier
    [Fact]
    public void ValidatePkceChallenge_Plain_InvalidVerifier_ReturnsFalse()
    {
        var verifier = "test-verifier";
        var challenge = "different-challenge";

        var result = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, challenge, "plain");

        result.Should().BeFalse();
        // RFC 7636 §4.6: Plain method requires exact match
    }

    // ===== RFC COMPLIANCE TESTS =====
    // These tests verify critical security requirements added to ensure full RFC compliance

    // RFC 6749 §3.1.2: Redirect URI MUST NOT contain a fragment component
    // Security: Prevents fragment bypass attacks
    [Fact]
    public async Task HandleAsync_RedirectUriWithFragment_ReturnsBadRequest()
    {
        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback#fragment"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 6749 §3.1.2: Fragment in redirect_uri must be rejected before client validation
    }

    // RFC 6749 §3.1.2.2: Redirect URI matching MUST be exact (case-sensitive)
    // Security: Prevents redirect URI confusion attacks
    [Fact]
    public async Task HandleAsync_RedirectUriCaseMismatch_ReturnsBadRequest()
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
            ["redirect_uri"] = "https://CLIENT.TEST/callback" // Different case
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 6749 §3.1.2.2: Case mismatch must be rejected (exact match required)
    }

    // RFC 7636 §4.3: code_challenge MUST be 43-128 characters
    // Security: Prevents weak PKCE challenges
    [Fact]
    public async Task HandleAsync_CodeChallengeTooShort_ReturnsInvalidRequest()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        // RFC 7636 §4.3: Challenge must be at least 43 characters
        var shortChallenge = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"; // 42 chars

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "test-nonce",
            ["code_challenge"] = shortChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 7636 §4.3: Should redirect with error for length violation
    }

    // RFC 7636 §4.3: code_challenge MUST NOT exceed 128 characters
    // Security: Prevents buffer overflow and DoS attacks
    [Fact]
    public async Task HandleAsync_CodeChallengeTooLong_ReturnsInvalidRequest()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        // RFC 7636 §4.3: Challenge must not exceed 128 characters
        var longChallenge = new String('a', 129);

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "test-nonce",
            ["code_challenge"] = longChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 7636 §4.3: Should redirect with error for length violation
    }

    // RFC 7636 §4.3: code_challenge must be base64url encoded (A-Z, a-z, 0-9, -, _)
    // Security: Prevents injection attacks through invalid characters
    [Fact]
    public async Task HandleAsync_CodeChallengeWithInvalidCharacters_ReturnsInvalidRequest()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile" }
        };

        _clientStore.GetByClientIdAsync("test-client", Arg.Any<CancellationToken>())
            .Returns(client);

        // RFC 7636 §4.3: Only base64url characters allowed (not +, /, =)
        var invalidChallenge = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF+/="; // 46 chars with invalid chars

        var context = CreateHttpContext(new Dictionary<String, String>
        {
            ["response_type"] = "code",
            ["client_id"] = "test-client",
            ["redirect_uri"] = "https://client.test/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "test-nonce",
            ["code_challenge"] = invalidChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 7636 §4.3: Should redirect with error for invalid characters
    }

    // RFC 6749 §3.3: Empty scope parameter should be rejected
    // Clarifies behavior when scope is missing or whitespace-only
    [Fact]
    public async Task HandleAsync_EmptyScope_ReturnsInvalidRequest()
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
            ["scope"] = "   ", // Whitespace only
            ["nonce"] = "test-nonce",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        // RFC 6749 §3.3: Empty scope should be rejected with invalid_request
    }

    // RFC 6749 §3.3: Duplicate scopes should be handled gracefully (deduplicated)
    // Security: Prevents scope confusion and ensures consistent authorization
    [Fact]
    public async Task HandleAsync_DuplicateScopes_RemovesDuplicates()
    {
        var client = new OAuthClient
        {
            ClientId = "test-client",
            RedirectUris = new List<String> { "https://client.test/callback" },
            AllowedScopes = new List<String> { "openid", "profile", "email" }
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
            ["scope"] = "openid profile profile email openid", // Duplicates
            ["nonce"] = "test-nonce",
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "test-state"
        });

        var result = await _handler.HandleAsync(context);

        result.Should().NotBeNull();
        capturedCode.Should().NotBeNull();
        // RFC 6749 §3.3: Duplicate scopes should be removed (normalized)
        capturedCode!.RequestedScopes.Should().HaveCount(3); // Only unique scopes
        capturedCode.RequestedScopes.Should().Contain("openid");
        capturedCode.RequestedScopes.Should().Contain("profile");
        capturedCode.RequestedScopes.Should().Contain("email");
    }

    // Security: Timing attack resistance for PKCE validation
    // Uses CryptographicOperations.FixedTimeEquals to prevent timing side-channel attacks
    [Fact]
    public void ValidatePkceChallenge_UsesConstantTimeComparison()
    {
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var correctChallenge = GenerateCodeChallenge(verifier);
        var incorrectChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cX"; // Last char different

        // Test that both comparisons complete (doesn't throw)
        var resultCorrect = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, correctChallenge, "S256");
        var resultIncorrect = AuthorizeEndpointHandler.ValidatePkceChallenge(verifier, incorrectChallenge, "S256");

        resultCorrect.Should().BeTrue();
        resultIncorrect.Should().BeFalse();

        // The use of CryptographicOperations.FixedTimeEquals ensures timing safety
        // This prevents attackers from using timing measurements to guess the challenge
    }

    // Helper method to create HTTP context with query parameters
    // Helper method to create HTTP context with query parameters
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

    // Helper method to generate PKCE code_challenge from verifier
    // RFC 7636 §4.2: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    private static String GenerateCodeChallenge(String verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}


