using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Solster.Authentication.OpenIdConnect.Abstractions;

namespace Solster.Authentication.OpenIdConnect;

// Test-only in-memory signing key store
public class InMemorySigningKeyStore : ISigningKeyStore, IDisposable
{
    private RsaSecurityKey _key;
    private readonly Object _lock = new();
    private String _kid;

    public InMemorySigningKeyStore()
    {
        (_key, _kid) = CreateNewKey();
    }

    private static (RsaSecurityKey key, String kid) CreateNewKey()
    {
        var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa)
        {
            KeyId = Guid.NewGuid().ToString("N")
        };
        return (key, key.KeyId);
    }

    public JsonWebKeySet GetCurrentKeySet()
    {
        lock (_lock)
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_key);
            jwk.Kid = _kid;
            jwk.Use = "sig";
            jwk.Alg = SecurityAlgorithms.RsaSha256;

            return new JsonWebKeySet() { Keys = { jwk } };
        }
    }

    public IEnumerable<JsonWebKey> GetPublicKeys()
    {
        lock (_lock)
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_key);
            jwk.Kid = _kid;
            jwk.Use = "sig";
            jwk.Alg = SecurityAlgorithms.RsaSha256;
            return [jwk];
        }
    }

    public SigningCredentials GetCurrentSigningCredentials()
    {
        lock (_lock)
        {
            var creds = new SigningCredentials(_key, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            return creds;
        }
    }

    public Task RotateAsync()
    {
        lock (_lock)
        {
            (_key, _kid) = CreateNewKey();
        }
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        (_key.Rsa as IDisposable)?.Dispose();
    }
}