using Microsoft.IdentityModel.Tokens;

namespace Solster.Authentication.OpenIdConnect.Abstractions;

/// <summary>
/// Abstraction for managing signing keys used to sign tokens.
/// </summary>
public interface ISigningKeyStore
{
    /// <summary>
    /// Gets the current signing credentials for creating tokens.
    /// </summary>
    /// <returns>Signing credentials with private key.</returns>
    SigningCredentials GetCurrentSigningCredentials();

    /// <summary>
    /// Gets the current public key set for token validation (published at JWKS endpoint).
    /// </summary>
    /// <returns>JSON Web Key Set containing public keys.</returns>
    JsonWebKeySet GetCurrentKeySet();
}
