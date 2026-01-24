using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryClientStore : IClientStore
{
    private readonly Dictionary<Guid, OAuthClient> _clientsById = new();
    private readonly Dictionary<String, OAuthClient> _clientsByClientId = new();

    public Task<OAuthClient?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        _clientsById.TryGetValue(id, out var client);
        return Task.FromResult(client);
    }

    public Task<OAuthClient?> GetByClientIdAsync(String clientId, CancellationToken cancellationToken = default)
    {
        _clientsByClientId.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }

    public Task<OAuthClient> CreateAsync(OAuthClient client, CancellationToken cancellationToken = default)
    {
        if (client.Id == Guid.Empty)
            client.Id = Guid.NewGuid();

        _clientsById[client.Id] = client;
        _clientsByClientId[client.ClientId] = client;
        return Task.FromResult(client);
    }

    public Task<OAuthClient> UpdateAsync(OAuthClient client, CancellationToken cancellationToken = default)
    {
        client.UpdatedAt = DateTimeOffset.UtcNow;
        _clientsById[client.Id] = client;
        _clientsByClientId[client.ClientId] = client;
        return Task.FromResult(client);
    }

    public Task<Boolean> DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        if (_clientsById.TryGetValue(id, out var client))
        {
            _clientsById.Remove(id);
            _clientsByClientId.Remove(client.ClientId);
            return Task.FromResult(true);
        }
        return Task.FromResult(false);
    }

    public Task<OAuthClient?> ValidateClientAsync(String clientId, String? clientSecret = null, CancellationToken cancellationToken = default)
    {
        if (!_clientsByClientId.TryGetValue(clientId, out var client))
            return Task.FromResult<OAuthClient?>(null);

        // For public clients, no secret validation needed
        if (client.ClientType == ClientType.Public && String.IsNullOrEmpty(clientSecret))
            return Task.FromResult<OAuthClient?>(client);

        // For confidential clients, validate secret
        if (client.ClientType == ClientType.Confidential && !String.IsNullOrEmpty(clientSecret))
        {
            // Simple hash comparison for testing - in production, use proper hashing (BCrypt, etc.)
            if (client.Secrets.Any(s => s.SecretHash == clientSecret))
                return Task.FromResult<OAuthClient?>(client);
        }

        return Task.FromResult<OAuthClient?>(null);
    }

    public Task<IEnumerable<OAuthClient>> ListAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult<IEnumerable<OAuthClient>>(_clientsById.Values);
    }

    public Task<ClientSecret> AddSecretAsync(Guid clientId, ClientSecret secret, CancellationToken cancellationToken = default)
    {
        if (_clientsById.TryGetValue(clientId, out var client))
        {
            client.Secrets.Add(secret);
        }
        return Task.FromResult(secret);
    }

    public Task<Boolean> RemoveSecretAsync(Guid clientId, Guid secretId, CancellationToken cancellationToken = default)
    {
        if (_clientsById.TryGetValue(clientId, out var client))
        {
            var secret = client.Secrets.FirstOrDefault(s => s.Id == secretId);
            if (secret != null)
            {
                client.Secrets.Remove(secret);
                return Task.FromResult(true);
            }
        }
        return Task.FromResult(false);
    }
}
