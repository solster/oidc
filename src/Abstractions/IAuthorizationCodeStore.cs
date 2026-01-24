using Solster.Authentication.OpenIdConnect.Models;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for storing and retrieving authorization codes.
/// </summary>
public interface IAuthorizationCodeStore
{
    /// <summary>
    /// Creates a new authorization code.
    /// </summary>
    /// <param name="code">The authorization code to create.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created authorization code.</returns>
    Task<AuthorizationCode> CreateCodeAsync(AuthorizationCode code, CancellationToken cancellationToken = default);

    /// <summary>
    /// Consumes an authorization code (single-use). The code is marked as consumed and cannot be used again.
    /// </summary>
    /// <param name="code">The authorization code value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The authorization code if valid and not yet consumed, otherwise null.</returns>
    Task<AuthorizationCode?> ConsumeCodeAsync(String code, CancellationToken cancellationToken = default);
}
