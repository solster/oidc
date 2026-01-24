using System.Security.Claims;
using Solster.Authentication.OpenIdConnect.Abstractions;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryTokenClaimsProvider : ITokenClaimsProvider
{
    public Task<IEnumerable<Claim>> GetIdTokenClaimsAsync(String userId, String clientId, IEnumerable<String> scopes, CancellationToken cancellationToken = default)
    {
        var claims = new List<Claim>();
        var scopeList = scopes.ToList();
        
        if (scopeList.Contains("profile"))
        {
            claims.Add(new Claim("name", "Test User"));
        }
        
        if (scopeList.Contains("email"))
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
        var claims = new List<Claim>();
        var scopeList = scopes.ToList();
        
        // Profile scope claims (OIDC Core §5.4)
        if (scopeList.Contains("profile"))
        {
            claims.Add(new Claim("name", "Test User"));
            claims.Add(new Claim("given_name", "Test"));
            claims.Add(new Claim("family_name", "User"));
            claims.Add(new Claim("preferred_username", "testuser"));
        }
        
        // Email scope claims (OIDC Core §5.4)
        if (scopeList.Contains("email"))
        {
            claims.Add(new Claim("email", "test@example.com"));
            claims.Add(new Claim("email_verified", "true"));
        }
        
        return Task.FromResult<IEnumerable<Claim>>(claims);
    }
}
