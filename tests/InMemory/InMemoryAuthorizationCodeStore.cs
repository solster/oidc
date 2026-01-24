using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly Dictionary<String, AuthorizationCode> _codes = new();
    private readonly object _lock = new();
    private const Int32 MaxCodeLength = 512; // Reasonable limit to prevent DoS

    public Task<AuthorizationCode> CreateCodeAsync(AuthorizationCode code, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        
        lock (_lock)
        {
            _codes[code.Code] = code;
        }
        
        return Task.FromResult(code);
    }

    public Task<AuthorizationCode?> GetCodeAsync(String code, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            // Uniform code path to prevent timing attacks; validate length to prevent DoS
            if (String.IsNullOrWhiteSpace(code) || code.Length > MaxCodeLength || !_codes.TryGetValue(code, out var authCode))
                return Task.FromResult<AuthorizationCode?>(null);

            return Task.FromResult<AuthorizationCode?>(authCode);
        }
    }

    public Task<AuthorizationCode?> ConsumeCodeAsync(String code, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            // Uniform code path to prevent timing attacks; validate length to prevent DoS
            if (String.IsNullOrWhiteSpace(code) || code.Length > MaxCodeLength || !_codes.TryGetValue(code, out var authCode))
                return Task.FromResult<AuthorizationCode?>(null);

            // Already consumed (should only happen in race conditions - handler checks IsConsumed first)
            if (authCode.IsConsumed)
                return Task.FromResult<AuthorizationCode?>(null);

            // RFC 6749 §4.1.2: Expired codes should not be consumed
            if (authCode.ExpiresAt < DateTimeOffset.UtcNow)
                return Task.FromResult<AuthorizationCode?>(null);

            // Mark as consumed
            authCode.IsConsumed = true;
            authCode.ConsumedAt = DateTimeOffset.UtcNow;

            return Task.FromResult<AuthorizationCode?>(authCode);
        }
    }
}
