using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Solster.Authentication.OpenIdConnect.Abstractions;

namespace Solster.Authentication.OpenIdConnect.Signing;

/// <summary>
/// Signing key store that reads RSA key parameters from configuration.
/// Keys can come from Azure KeyVault (via App Configuration), local config, environment variables, etc.
/// </summary>
public class ConfigurationSigningKeyStore(IConfiguration configuration) : ISigningKeyStore
{
    private RsaSecurityKey? _cachedKey;

    public SigningCredentials GetCurrentSigningCredentials()
    {
        var key = GetOrCreateKey();
        return new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        {
            CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
        };
    }

    public JsonWebKeySet GetCurrentKeySet()
    {
        var jwk = GetJsonWebKey();
        var keySet = new JsonWebKeySet();
        keySet.Keys.Add(jwk);
        return keySet;
    }

    private JsonWebKey GetJsonWebKey()
    {
        var key = GetOrCreateKey();
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Kid = key.KeyId;
        jwk.Use = "sig";
        jwk.Alg = SecurityAlgorithms.RsaSha256;
        return jwk;
    }

    private RsaSecurityKey GetOrCreateKey()
    {
        if (_cachedKey != null)
            return _cachedKey;

        // Try to load from configuration
        var n = configuration["OpenIdConnect:SigningKey:N"];
        var e = configuration["OpenIdConnect:SigningKey:E"];
        var keyId = configuration["OpenIdConnect:SigningKey:KeyId"];

        if (!String.IsNullOrEmpty(n) && !String.IsNullOrEmpty(e))
        {
            // Load RSA key from configuration
            var rsa = RSA.Create();
            var parameters = new RSAParameters
            {
                Modulus = Base64UrlEncoder.DecodeBytes(n),
                Exponent = Base64UrlEncoder.DecodeBytes(e)
            };
            rsa.ImportParameters(parameters);

            _cachedKey = new RsaSecurityKey(rsa)
            {
                KeyId = keyId ?? Guid.NewGuid().ToString("N")
            };
        }
        else
        {
            // Generate ephemeral key for development (not recommended for production)
            var rsa = RSA.Create(2048);
            _cachedKey = new RsaSecurityKey(rsa)
            {
                KeyId = Guid.NewGuid().ToString("N")
            };
        }

        return _cachedKey;
    }
}
