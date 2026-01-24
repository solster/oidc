using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Solster.Authentication.OpenIdConnect.Infrastructure;

/// <summary>
/// Singleton manager for OIDC configuration and JWKS with built-in caching.
/// Prevents per-request JWKS fetches and handles network failures gracefully.
/// </summary>
public class JwksConfigurationManager : IDisposable
{
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
    private readonly ILogger<JwksConfigurationManager> _logger;
    private readonly String _issuer;

    public JwksConfigurationManager(
        IOptions<OpenIdConnectOptions> options,
        ILogger<JwksConfigurationManager> logger)
    {
        var opts = options.Value;
        _issuer = opts.Issuer;
        _logger = logger;

        // ConfigurationManager handles caching automatically (24h default refresh)
        _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            $"{opts.Issuer}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever())
        {
            // Refresh configuration every hour to detect key rotations
            AutomaticRefreshInterval = TimeSpan.FromHours(1),
            // Keep configuration for 24 hours even if refresh fails
            RefreshInterval = TimeSpan.FromHours(24)
        };

        _logger.LogInformation("JWKS Configuration Manager initialized for issuer {Issuer}", _issuer);
    }

    /// <summary>
    /// Gets the current OIDC configuration with JWKS.
    /// Cached automatically by ConfigurationManager.
    /// </summary>
    public async Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var config = await _configurationManager.GetConfigurationAsync(cancellationToken);
            
            if (config?.JsonWebKeySet?.Keys == null || config.JsonWebKeySet.Keys.Count == 0)
            {
                _logger.LogError("JWKS configuration retrieved but contains no keys for issuer {Issuer}", _issuer);
                throw new InvalidOperationException("JWKS contains no signing keys");
            }

            _logger.LogDebug("JWKS configuration retrieved successfully for {Issuer}. Keys count: {KeyCount}", 
                _issuer, config.JsonWebKeySet.Keys.Count);

            return config;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network error fetching JWKS from {Issuer}", _issuer);
            throw new InvalidOperationException("Unable to fetch JWKS configuration due to network error", ex);
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogError(ex, "Timeout fetching JWKS from {Issuer}", _issuer);
            throw new InvalidOperationException("Timeout while fetching JWKS configuration", ex);
        }
        catch (IOException ex)
        {
            _logger.LogError(ex, "I/O error fetching JWKS from {Issuer}", _issuer);
            throw new InvalidOperationException("I/O error while fetching JWKS configuration", ex);
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            _logger.LogError(ex, "Unexpected error fetching JWKS from {Issuer}", _issuer);
            throw new InvalidOperationException("Unexpected error while fetching JWKS configuration", ex);
        }
    }

    /// <summary>
    /// Forces a refresh of the configuration (useful for key rotation scenarios).
    /// </summary>
    public void RequestRefresh()
    {
        _configurationManager.RequestRefresh();
        _logger.LogInformation("JWKS configuration refresh requested for {Issuer}", _issuer);
    }

    public void Dispose()
    {
        // ConfigurationManager does not implement IDisposable, no cleanup needed
    }
}
