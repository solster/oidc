using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.UnitTests;

public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly Dictionary<String, AuthorizationCode> _codes = new();

    public Task<AuthorizationCode> CreateCodeAsync(AuthorizationCode code, CancellationToken cancellationToken = default)
    {
        _codes[code.Code] = code;
        return Task.FromResult(code);
    }

    public Task<AuthorizationCode?> ConsumeCodeAsync(String code, CancellationToken cancellationToken = default)
    {
        if (!_codes.TryGetValue(code, out var authCode))
            return Task.FromResult<AuthorizationCode?>(null);

        // Check if already consumed
        if (authCode.IsConsumed)
            return Task.FromResult<AuthorizationCode?>(null);

        // Check if expired
        if (authCode.ExpiresAt < DateTimeOffset.UtcNow)
            return Task.FromResult<AuthorizationCode?>(null);

        // Mark as consumed
        authCode.IsConsumed = true;
        authCode.ConsumedAt = DateTimeOffset.UtcNow;

        return Task.FromResult<AuthorizationCode?>(authCode);
    }
}
