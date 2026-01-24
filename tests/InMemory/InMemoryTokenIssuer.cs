using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Solster.Authentication.OpenIdConnect.Abstractions;

namespace Solster.Authentication.OpenIdConnect;

public class InMemoryTokenIssuer : ITokenIssuer
{
    public Task<String> IssueIdTokenAsync(String userId, String clientId, String? nonce, DateTimeOffset authTime, IEnumerable<Claim> additionalClaims, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        var claims = new Dictionary<String, Object>
        {
            ["iss"] = "https://issuer.test",
            ["sub"] = userId,
            ["aud"] = clientId,
            ["exp"] = DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["auth_time"] = authTime.ToUnixTimeSeconds()
        };

        if (!String.IsNullOrEmpty(nonce))
            claims["nonce"] = nonce;

        foreach (var claim in additionalClaims)
            claims[claim.Type] = claim.Value;

        var token = CreateMockJwt(claims);
        return Task.FromResult(token);
    }

    public Task<String> IssueAccessTokenAsync(String userId, String clientId, IEnumerable<String> scopes, IEnumerable<Claim> additionalClaims, TimeSpan lifetime, CancellationToken cancellationToken = default)
    {
        var claims = new Dictionary<String, Object>
        {
            ["iss"] = "https://issuer.test",
            ["sub"] = userId,
            ["aud"] = clientId,
            ["exp"] = DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds(),
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString(),
            ["scope"] = String.Join(" ", scopes)
        };

        foreach (var claim in additionalClaims)
            claims[claim.Type] = claim.Value;

        var token = CreateMockJwt(claims);
        return Task.FromResult(token);
    }

    public Task<String> IssueRefreshTokenAsync(String userId, String clientId, IEnumerable<String> scopes, CancellationToken cancellationToken = default)
    {
        var bytes = new Byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Task.FromResult(Convert.ToBase64String(bytes));
    }

    private static String CreateMockJwt(Dictionary<String, Object> claims)
    {
        var header = new { alg = "RS256", typ = "JWT" };
        var headerJson = JsonSerializer.Serialize(header);
        var payloadJson = JsonSerializer.Serialize(claims);

        var headerBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        var payloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var signature = Base64UrlEncode(new Byte[64]);

        return String.Format("{0}.{1}.{2}", headerBase64, payloadBase64, signature);
    }

    private static String Base64UrlEncode(Byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
