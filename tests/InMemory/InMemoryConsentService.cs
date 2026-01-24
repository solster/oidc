using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryConsentService : IConsentService
{
    private readonly Dictionary<String, HashSet<String>> _consents = new(); // userId:clientId -> scopes

    public Task<Boolean> RequiresConsentAsync(String userId, String clientId, IEnumerable<String> requestedScopes, CancellationToken cancellationToken = default)
    {
        var key = $"{userId}:{clientId}";
        if (!_consents.TryGetValue(key, out var grantedScopes))
            return Task.FromResult(true);

        // Check if all requested scopes are already granted
        var scopesList = requestedScopes.ToList();
        var allGranted = scopesList.All(s => grantedScopes.Contains(s));
        return Task.FromResult(!allGranted);
    }

    public Task<ConsentGrant> GrantConsentAsync(String userId, String clientId, IEnumerable<String> grantedScopes, CancellationToken cancellationToken = default)
    {
        var key = $"{userId}:{clientId}";
        _consents[key] = new HashSet<String>(grantedScopes);

        var grant = new ConsentGrant
        {
            UserId = userId,
            ClientId = clientId,
            GrantedScopes = grantedScopes.ToList(),
            GrantedAt = DateTimeOffset.UtcNow
        };

        return Task.FromResult(grant);
    }

    public Task<Boolean> RevokeConsentAsync(String userId, String clientId, CancellationToken cancellationToken = default)
    {
        var key = $"{userId}:{clientId}";
        return Task.FromResult(_consents.Remove(key));
    }

    public Task<IEnumerable<ConsentGrant>> ListUserConsentsAsync(String userId, CancellationToken cancellationToken = default)
    {
        var grants = _consents
            .Where(kvp => kvp.Key.StartsWith($"{userId}:"))
            .Select(kvp =>
            {
                var clientId = kvp.Key.Substring(kvp.Key.IndexOf(':') + 1);
                return new ConsentGrant
                {
                    UserId = userId,
                    ClientId = clientId,
                    GrantedScopes = kvp.Value.ToList(),
                    GrantedAt = DateTimeOffset.UtcNow
                };
            });

        return Task.FromResult(grants);
    }
}
