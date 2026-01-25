using System.Collections.Concurrent;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect;

/// <summary>
/// In-memory implementation of IRefreshTokenStore for testing and development.
/// NOT FOR PRODUCTION USE - data is lost on application restart.
/// </summary>
public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ConcurrentDictionary<String, RefreshToken> _tokens = new();
    private readonly ConcurrentDictionary<String, String> _revokedTokens = new();

    public Task<RefreshToken> SaveTokenAsync(RefreshToken token, CancellationToken cancellationToken = default)
    {
        _tokens[token.TokenHash] = token;
        return Task.FromResult(token);
    }

    public Task<RefreshToken?> ConsumeAndRotateAsync(String tokenValue, CancellationToken cancellationToken = default)
    {
        var token = _tokens.Values.FirstOrDefault(t => t.TokenHash == tokenValue);
        
        if (token == null)
            return Task.FromResult<RefreshToken?>(null);

        // Check if already consumed
        if (token.ConsumedAt.HasValue)
        {
            // Token reuse detected - revoke entire family
            RevokeTokenFamilyAsync(token.TokenHash, "Token reuse detected").Wait(cancellationToken);
            return Task.FromResult<RefreshToken?>(null);
        }

        // Mark as consumed
        token.ConsumedAt = DateTime.UtcNow;
        _tokens[token.TokenHash] = token;

        return Task.FromResult<RefreshToken?>(token);
    }

    public Task<Boolean> RevokeTokenAsync(String tokenValue, String? reason = null, CancellationToken cancellationToken = default)
    {
        var token = _tokens.Values.FirstOrDefault(t => t.TokenHash == tokenValue);
        
        if (token != null)
        {
            _revokedTokens[token.TokenHash] = reason ?? "revoked";
            return Task.FromResult(true);
        }

        // RFC 7009: Even if token doesn't exist, consider it "revoked"
        return Task.FromResult(false);
    }

    public Task<RefreshToken?> GetByTokenHashAsync(String tokenHash, CancellationToken cancellationToken = default)
    {
        _tokens.TryGetValue(tokenHash, out var token);
        return Task.FromResult(token);
    }

    public Task<Int32> RevokeAllForClientAsync(String userId, String clientId, String? reason = null, CancellationToken cancellationToken = default)
    {
        var tokensToRevoke = _tokens.Values
            .Where(t => t.UserId == userId && t.ClientId == clientId)
            .ToList();

        foreach (var token in tokensToRevoke)
        {
            _revokedTokens[token.TokenHash] = reason ?? "revoked";
        }

        return Task.FromResult(tokensToRevoke.Count);
    }

    /// <summary>
    /// Checks if a refresh token is revoked.
    /// </summary>
    public Task<Boolean> IsRevokedAsync(String tokenId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_revokedTokens.ContainsKey(tokenId));
    }

    /// <summary>
    /// Revokes an entire token family (used when token reuse is detected).
    /// </summary>
    private Task RevokeTokenFamilyAsync(String tokenHash, String reason)
    {
        var token = _tokens.GetValueOrDefault(tokenHash);
        if (token == null)
            return Task.CompletedTask;

        // Revoke all tokens in the same family
        var familyTokens = _tokens.Values
            .Where(t => t.TokenFamily == token.TokenFamily)
            .ToList();

        foreach (var familyToken in familyTokens)
        {
            _revokedTokens[familyToken.TokenHash] = reason;
        }

        return Task.CompletedTask;
    }
}
