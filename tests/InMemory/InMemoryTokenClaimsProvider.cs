using System.Security.Claims;
using Solster.Authentication.OpenIdConnect.Abstractions;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryTokenClaimsProvider : ITokenClaimsProvider
{
    public Task<IEnumerable<Claim>> GetIdTokenClaimsAsync(String userId, String clientId, IEnumerable<String> scopes, CancellationToken cancellationToken = default)
    {
        var claims = new List<Claim>();
        
        if (scopes.Contains("profile"))
        {
            claims.Add(new Claim("name", "Test User"));
        }
        
        if (scopes.Contains("email"))
        {
            claims.Add(new Claim("email", "test@example.com"));
        }
        
        return Task.FromResult<IEnumerable<Claim>>(claims);
    }

    public Task<IEnumerable<Claim>> GetAccessTokenClaimsAsync(String userId, String clientId, IEnumerable<String> scopes, CancellationToken cancellationToken = default)
    {
        var claims = new List<Claim>();
        return Task.FromResult<IEnumerable<Claim>>(claims);
    }

    public Task<IEnumerable<Claim>> GetUserInfoClaimsAsync(String userId, IEnumerable<String> scopes, CancellationToken cancellationToken = default)
    {
        var claims = new List<Claim>
        {
            new Claim("sub", userId)
        };
        
        return Task.FromResult<IEnumerable<Claim>>(claims);
    }
}
