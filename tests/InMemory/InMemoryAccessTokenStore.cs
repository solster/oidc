using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryAccessTokenStore : IAccessTokenStore
{
    private readonly Dictionary<String, AccessTokenReference> _tokens = new();
    private readonly HashSet<String> _revokedTokens = new();

    public Task<AccessTokenReference> SaveTokenAsync(AccessTokenReference token, CancellationToken cancellationToken = default)
    {
        _tokens[token.TokenId] = token;
        return Task.FromResult(token);
    }

    public Task<Boolean> RevokeTokenAsync(String tokenId, CancellationToken cancellationToken = default)
    {
        _revokedTokens.Add(tokenId);
        return Task.FromResult(true);
    }

    public Task<Boolean> IsRevokedAsync(String tokenId, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_revokedTokens.Contains(tokenId));
    }

    public Task<Int32> RevokeTokensByAuthorizationCodeAsync(String authorizationCode, CancellationToken cancellationToken = default)
    {
        var tokensToRevoke = _tokens.Values
            .Where(t => t.AuthorizationCode == authorizationCode)
            .Select(t => t.TokenId)
            .ToList();
        
        foreach (var tokenId in tokensToRevoke)
        {
            _revokedTokens.Add(tokenId);
        }
        
        return Task.FromResult(tokensToRevoke.Count);
    }
}
