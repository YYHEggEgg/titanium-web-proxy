using System.Net;
using System.Net.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Titanium.Web.Proxy.Models;
using Xunit;

namespace Titanium.Web.Proxy.TracebackTests;

public sealed class BodyBoundaryTests
{
    private static CancellationToken Token => TestContext.Current.CancellationToken;
    public static IEnumerable<object[]> BodylessCases =>
        from client in new[] { 1, 2 }
        from origin in new[] { 1, 2 }
        from kind in new[] { "head", "204", "304", "zero" }
        select new object[] { client, origin, kind };

    [Theory]
    [MemberData(nameof(BodylessCases))]
    public async Task EmptyAndSemanticallyBodylessResponsesEndOnce(int clientVersion, int originVersion, string kind)
    {
        await RunAsync(clientVersion, originVersion, context =>
        {
            context.Response.StatusCode = kind switch { "204" => 204, "304" => 304, _ => 200 };
            if (kind == "head") context.Response.ContentLength = 123;
            else if (kind == "zero") context.Response.ContentLength = 0;
            return Task.CompletedTask;
        }, async (proxy, client, url) =>
        {
            var ends = 0;
            var bytes = 0;
            proxy.OnResponseBodyWrite += (_, args) =>
            {
                bytes += args.BodyBytes.Length;
                if (args.IsLastChunk) ends++;
                return Task.CompletedTask;
            };
            using var request = Request(clientVersion, kind == "head" ? HttpMethod.Head : HttpMethod.Get, url);
            using var response = await client.SendAsync(request, Token);
            Assert.Empty(await response.Content.ReadAsByteArrayAsync(Token));
            await proxy.StopAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(0, bytes);
            Assert.Equal(1, ends);
        });
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 2)]
    [InlineData(2, 1)]
    [InlineData(2, 2)]
    public async Task ExplicitWholeBodyReadStillEnforcesItsLimit(int clientVersion, int originVersion)
    {
        await RunAsync(clientVersion, originVersion, async context =>
        {
            context.Response.ContentLength = 32_000;
            await context.Response.Body.WriteAsync(new byte[32_000], context.RequestAborted);
        }, async (proxy, client, url) =>
        {
            proxy.MaxBufferedBodyBytes = 1024;
            var rejected = new TaskCompletionSource<Exception>(TaskCreationOptions.RunContinuationsAsynchronously);
            proxy.BeforeResponse += async (_, args) =>
            {
                try { await args.GetResponseBody(Token); }
                catch (Exception error) { rejected.TrySetResult(error); throw; }
            };
            using var request = Request(clientVersion, HttpMethod.Get, url);
            var transport = await Record.ExceptionAsync(async () =>
            {
                using var response = await client.SendAsync(request, Token);
                Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
            });
            Assert.IsNotType<TimeoutException>(transport);
            var failure = await rejected.Task.WaitAsync(TimeSpan.FromSeconds(5), Token);
            Assert.Contains("BodySizeLimitExceededException", failure.ToString());
        });
    }

    private static HttpRequestMessage Request(int version, HttpMethod method, string url) => new(method, url)
    {
        Version = version == 2 ? HttpVersion.Version20 : HttpVersion.Version11,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact
    };

    private static async Task RunAsync(int clientVersion, int originVersion, RequestDelegate handler,
        Func<ProxyServer, HttpClient, string, Task> check)
    {
        Network.CertificateManager.SuppressInteractiveRootStoreMutations = true;
        using var root = CoreRegressionTests.Certificate(true);
        using var certificate = CoreRegressionTests.Certificate(false);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listener =>
        {
            listener.Protocols = originVersion == 2 ? HttpProtocols.Http2 : HttpProtocols.Http1;
            listener.UseHttps(certificate);
        }));
        await using var origin = builder.Build();
        origin.Run(handler);
        await origin.StartAsync(Token);
        using var proxy = CoreRegressionTests.Proxy(root);
        proxy.ServerCertificateValidationCallback += (_, args) =>
        {
            args.IsValid = args.Certificate?.GetCertHashString() == certificate.Thumbprint;
            return Task.CompletedTask;
        };
        var endpoint = new ExplicitProxyEndPoint(IPAddress.Loopback, 0, true);
        endpoint.BeforeTunnelConnectRequest += (_, args) =>
        {
            args.UpstreamHttpProtocol = originVersion == 2 ? UpstreamHttpProtocol.Http2 : UpstreamHttpProtocol.Http11;
            args.AllowHttpProtocolTranslation = true;
            return Task.CompletedTask;
        };
        // Disable fast paths so observation is exercised even when the body is empty.
        proxy.BeforeRequest += (_, _) => Task.CompletedTask;
        proxy.AddEndPoint(endpoint);
        proxy.Start();
        try
        {
            using var client = new HttpClient(new SocketsHttpHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{endpoint.Port}"),
                SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true }
            }) { Timeout = TimeSpan.FromSeconds(15) };
            await check(proxy, client, origin.Urls.Single());
        }
        finally
        {
            if (proxy.ProxyRunning) await proxy.StopAsync(TimeSpan.FromSeconds(5));
            await origin.StopAsync(Token);
        }
    }
}
