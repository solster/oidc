using Xunit;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Net;
using AwesomeAssertions;

namespace Solster.Authentication.OpenIdConnect.IntegrationTests;

public class DiscoveryIntegrationTests
{
    [Fact]
    public async Task Discovery_Returns_Correct_Issuer_And_Urls()
    {
        var hostBuilder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                
                webHost.ConfigureServices(services =>
                {
                    // Add routing services
                    services.AddRouting();
                    
                    // configure OpenIdConnectOptions
                    services.AddOpenIdConnect("https://issuer.test", opts =>
                    {
                        opts.PublicOrigin = "https://example.test";
                    });
                });

                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapOpenIdConnect();
                    });
                });
            });

        using var host = await hostBuilder.StartAsync();
        var client = host.GetTestClient();
        client.BaseAddress = new Uri("https://example.test");

        var res = await client.GetAsync("/.well-known/openid-configuration");
        res.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await res.Content.ReadAsStringAsync();
        json.Should().Contain("\"issuer\":\"https://issuer.test\"");
        json.Should().Contain("https://example.test/connect/token");
        res.Headers.CacheControl.Should().NotBeNull();
    }
}

