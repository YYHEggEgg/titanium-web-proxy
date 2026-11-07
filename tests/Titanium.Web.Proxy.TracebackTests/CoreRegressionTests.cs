using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Titanium.Web.Proxy.TracebackTests;

public sealed class CoreRegressionTests
{
    static CoreRegressionTests()
    {
        Titanium.Web.Proxy.Network.CertificateManager.SuppressInteractiveRootStoreMutations = true;
        Environment.SetEnvironmentVariable("TITANIUM_SKIP_ROOT_STORE_UI", "1");
    }
    private static CancellationToken Token => TestContext.Current.CancellationToken;

    internal static X509Certificate2 Certificate(bool root)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(root ? "CN=Isolated test root" : "CN=127.0.0.1", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(root, false, 0, true));
        if (!root)
        {
            var names = new SubjectAlternativeNameBuilder();
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
        }
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        // Schannel server keys must be accessible; importing a PFX does not install a trust anchor.
        return X509CertificateLoader.LoadPkcs12(generated.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
    }

    internal static ProxyServer Proxy(X509Certificate2 root)
    {
        var proxy = new ProxyServer(false, false, false);
        proxy.CertificateManager.RootCertificate = root;
        proxy.CertificateManager.SaveFakeCertificates = false;
        proxy.CertificateManager.EnsureRootCertificate(false, false, false);
        return proxy;
    }

    [Fact]
    public async Task ConcurrentSniNamesAndCacheHitsUseTheirOwnCertificates()
    {
        using var root = Certificate(true);
        using var proxy = Proxy(root);
        proxy.EnableHttp2 = false;
        var endpoint = new ExplicitProxyEndPoint(IPAddress.Loopback, 0, true);
        proxy.AddEndPoint(endpoint);
        proxy.Start();
        try
        {
            for (var round = 0; round < 2; round++)
            {
                var names = new[] { "api.test", "upload.test", "api.test", "upload.test" };
                var actual = await Task.WhenAll(names.Select(name => Handshake(endpoint.Port, "alias.test", name)));
                Assert.Equal(names, actual);
            }
        }
        finally { await proxy.StopAsync(TimeSpan.FromSeconds(5)); }
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("")]
    [InlineData("invalid host name")]
    public async Task NonDnsSniFallsBackToConnectName(string name)
    {
        using var root = Certificate(true);
        using var proxy = Proxy(root);
        proxy.EnableHttp2 = false;
        var endpoint = new ExplicitProxyEndPoint(IPAddress.Loopback, 0, true);
        proxy.AddEndPoint(endpoint);
        proxy.Start();
        try { Assert.Equal("alias.test", await Handshake(endpoint.Port, "alias.test", name)); }
        finally { await proxy.StopAsync(TimeSpan.FromSeconds(5)); }
    }

    [Fact]
    public async Task GenericCertificateKeepsPriorityOverSni()
    {
        using var root = Certificate(true);
        using var generic = Certificate(false);
        using var proxy = Proxy(root);
        proxy.EnableHttp2 = false;
        var endpoint = new ExplicitProxyEndPoint(IPAddress.Loopback, 0, true) { GenericCertificate = generic };
        proxy.AddEndPoint(endpoint);
        proxy.Start();
        try { Assert.Equal("127.0.0.1", await Handshake(endpoint.Port, "alias.test", "api.test")); }
        finally { await proxy.StopAsync(TimeSpan.FromSeconds(5)); }
    }

    private static async Task<string> Handshake(int port, string connect, string name)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        var stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes($"CONNECT {connect}:9 HTTP/1.1\r\nHost: {connect}:9\r\n\r\n"), timeout.Token);
        var header = new StringBuilder();
        var one = new byte[1];
        while (!header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            Assert.Equal(1, await stream.ReadAsync(one, timeout.Token));
            header.Append((char)one[0]);
            Assert.True(header.Length < 4096);
        }
        Assert.StartsWith("HTTP/1.1 200", header.ToString());
        using var tls = new SslStream(stream, false, (_, _, _, _) => true);
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = name }, timeout.Token);
        using var leaf = new X509Certificate2(tls.RemoteCertificate!);
        return leaf.GetNameInfo(X509NameType.SimpleName, false);
    }

    [Theory]
    [InlineData(1, 1, false)]
    [InlineData(1, 2, false)]
    [InlineData(2, 1, false)]
    [InlineData(2, 2, false)]
    [InlineData(1, 2, true)]
    [InlineData(2, 1, true)]
    public async Task StreamingHooksMatchForwardedBodies(int clientVersion, int originVersion, bool large)
    {
        using var root = Certificate(true);
        using var certificate = Certificate(false);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listener =>
        {
            listener.Protocols = originVersion == 2 ? HttpProtocols.Http2 : HttpProtocols.Http1;
            listener.UseHttps(certificate);
        }));
        await using var origin = builder.Build();
        var received = new ConcurrentBag<byte[]>();
        var payload = Enumerable.Range(0, large ? 5_000_000 : 48_017).Select(i => (byte)(i % 251)).ToArray();
        origin.Run(async context =>
        {
            using var body = new MemoryStream();
            await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            received.Add(body.ToArray());
            for (var offset = 0; offset < payload.Length; offset += 8193)
                await context.Response.Body.WriteAsync(payload.AsMemory(offset, Math.Min(8193, payload.Length - offset)), context.RequestAborted);
        });
        await origin.StartAsync(Token);
        using var proxy = Proxy(root);
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
        var observations = new ConcurrentDictionary<SessionEventArgs, Observed>();
        var completed = new ConcurrentBag<SessionEventArgs>();
        proxy.BeforeRequest += (_, args) => { observations.TryAdd(args, new()); return Task.CompletedTask; };
        proxy.BeforeResponse += (_, _) => Task.CompletedTask;
        proxy.OnRequestBodyWrite += (_, args) =>
        {
            var item = observations[args.Session];
            item.Request.Write(args.BodyBytes);
            if (args.IsLastChunk) item.RequestEnds++;
            return Task.CompletedTask;
        };
        proxy.OnResponseBodyWrite += (_, args) =>
        {
            var item = observations[args.Session];
            item.Response.Write(args.BodyBytes);
            if (args.IsLastChunk) item.ResponseEnds++;
            return Task.CompletedTask;
        };
        proxy.AfterResponse += (_, args) => { completed.Add(args); return Task.CompletedTask; };
        proxy.AddEndPoint(endpoint);
        proxy.Start();
        try
        {
            using var client = new HttpClient(new SocketsHttpHandler
            {
                Proxy = new WebProxy($"http://127.0.0.1:{endpoint.Port}"),
                SslOptions = new SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, _, _, _) => true }
            }) { Timeout = TimeSpan.FromSeconds(40) };
            var count = large ? 1 : 8;
            await Task.WhenAll(Enumerable.Range(0, count).Select(async _ =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, origin.Urls.Single())
                {
                    Version = clientVersion == 2 ? HttpVersion.Version20 : HttpVersion.Version11,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                    Content = new UnknownLengthContent(payload)
                };
                using var response = await client.SendAsync(request, Token);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                Assert.Equal(clientVersion, response.Version.Major);
                Assert.Equal(payload, await response.Content.ReadAsByteArrayAsync(Token));
            }));
            await proxy.StopAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(count, completed.Count);
            Assert.Equal(count, received.Count);
            Assert.All(received, body => Assert.Equal(payload, body));
            Assert.Equal(count, observations.Count);
            foreach (var item in observations.Values)
            {
                Assert.Equal(payload, item.Request.ToArray());
                Assert.Equal(payload, item.Response.ToArray());
                Assert.Equal(1, item.RequestEnds);
                Assert.Equal(1, item.ResponseEnds);
            }
        }
        finally { if (proxy.ProxyRunning) await proxy.StopAsync(TimeSpan.FromSeconds(5)); await origin.StopAsync(Token); }
    }

    private sealed class Observed
    {
        internal MemoryStream Request { get; } = new();
        internal MemoryStream Response { get; } = new();
        internal int RequestEnds;
        internal int ResponseEnds;
    }

    private sealed class UnknownLengthContent(byte[] bytes) : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => stream.WriteAsync(bytes).AsTask();
    }

    [Theory]
    [InlineData(false, "abc", 4)]
    [InlineData(true, "3\r\nabc\r\n", -1)]
    [InlineData(true, "3\r\nabc\r\n0\r\nX-Test: yes\r\n", -1)]
    public async Task IncompleteFramingCannotBecomeSuccessfulEof(bool chunked, string wire, long length)
    {
        using var proxy = new ProxyServer(false, false, false);
        using var input = new MemoryStream(Encoding.ASCII.GetBytes(wire));
        using var reader = HttpReader(proxy, input);
        using var limited = Limited(proxy, reader, chunked, length);
        var failure = await Record.ExceptionAsync(async () => await limited.CopyToAsync(Stream.Null, Token));
        Assert.NotNull(failure);
        Assert.IsNotType<TimeoutException>(failure);
    }

    [Fact]
    public async Task ChunkedFinishHonorsCancellationEvenAfterPayloadIsRead()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, Token);
        using var origin = await listener.AcceptTcpClientAsync(Token);
        await origin.GetStream().WriteAsync("1\r\na\r\n"u8.ToArray(), Token);
        using var proxy = new ProxyServer(false, false, false);
        using var reader = HttpReader(proxy, client.GetStream());
        using var limited = Limited(proxy, reader, true, -1);
        await limited.ReadExactlyAsync(new byte[1], Token);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var method = limited.GetType().GetMethod("Finish")!;
        var finish = (Task)method.Invoke(limited, method.GetParameters().Length == 0 ? [] : [cancellation.Token])!;
        try
        {
            var failure = await Record.ExceptionAsync(async () => await finish.WaitAsync(TimeSpan.FromSeconds(2), Token));
            Assert.IsAssignableFrom<OperationCanceledException>(failure);
        }
        finally
        {
            client.Dispose();
            try { await finish.WaitAsync(TimeSpan.FromSeconds(2), Token); } catch (Exception) { }
        }
    }

    internal static Stream HttpReader(ProxyServer proxy, Stream input) => (Stream)Activator.CreateInstance(
        typeof(ProxyServer).Assembly.GetType("Titanium.Web.Proxy.Helpers.HttpStream", true)!,
        BindingFlags.NonPublic | BindingFlags.Instance, null, [proxy, input, proxy.BufferPool, CancellationToken.None, false, true], null)!;

    internal static Stream Limited(ProxyServer proxy, Stream reader, bool chunked, long length) => (Stream)Activator.CreateInstance(
        typeof(ProxyServer).Assembly.GetType("Titanium.Web.Proxy.EventArguments.LimitedStream", true)!,
        BindingFlags.NonPublic | BindingFlags.Instance, null, [reader, proxy.BufferPool, chunked, length, null, 100, 16 * 1024], null)!;
}
