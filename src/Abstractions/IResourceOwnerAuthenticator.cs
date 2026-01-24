using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for authenticating resource owners (users) and retrieving authenticated user information.
/// </summary>
public interface IResourceOwnerAuthenticator
{
    /// <summary>
    /// Authenticates a user with provided credentials.
    /// This method is called during the authentication flow to verify user identity.
    /// </summary>
    /// <param name="context">The HTTP context containing authentication information.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authenticated user principal if authentication succeeds, otherwise null.</returns>
    Task<UserPrincipal?> AuthenticateAsync(HttpContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the currently authenticated user from the HTTP context.
    /// This method is called during authorization flow to check if a user is already authenticated.
    /// </summary>
    /// <param name="context">The HTTP context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authenticated user principal if authenticated, otherwise null.</returns>
    Task<UserPrincipal?> GetCurrentUserAsync(HttpContext context, CancellationToken cancellationToken = default);
}
