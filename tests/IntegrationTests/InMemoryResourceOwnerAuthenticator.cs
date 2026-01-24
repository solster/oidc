using Microsoft.AspNetCore.Http;
using Solster.Authentication.OpenIdConnect.Abstractions;
using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.IntegrationTests;

public class InMemoryResourceOwnerAuthenticator : IResourceOwnerAuthenticator
{
    private UserPrincipal? _currentUser;

    public void SetCurrentUser(UserPrincipal? user)
    {
        _currentUser = user;
    }

    public Task<UserPrincipal?> AuthenticateAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_currentUser);
    }

    public Task<UserPrincipal?> GetCurrentUserAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(_currentUser);
    }
}
