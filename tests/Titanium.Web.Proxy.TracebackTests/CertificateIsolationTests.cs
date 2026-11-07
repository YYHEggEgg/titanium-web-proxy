using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Titanium.Web.Proxy.TracebackTests;

public sealed class CertificateIsolationTests
{
    [Fact]
    public async Task TemporaryCaConfigurationAndDisposalLeaveUserStoresUntouched()
    {
        Network.CertificateManager.SuppressInteractiveRootStoreMutations = true;
        var before = ReadUserStores();
        using (var root = CoreRegressionTests.Certificate(true))
        using (var proxy = CoreRegressionTests.Proxy(root))
        {
            var leaf = await proxy.CertificateManager.CreateServerCertificate("isolation.example.test");
            Assert.NotNull(leaf);
            var options = new SslServerAuthenticationOptions();
            typeof(Network.CertificateManager).GetMethod("ConfigureServerCertificate", BindingFlags.Instance | BindingFlags.NonPublic)!
                .Invoke(proxy.CertificateManager, [options, leaf]);
            Assert.Same(leaf, options.ServerCertificate);
            Assert.Null(options.ServerCertificateContext);
        }
        Assert.Equal(before, ReadUserStores());
    }

    private static string[] ReadUserStores()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var result = new List<string>();
        foreach (var name in new[] { StoreName.My, StoreName.Root, StoreName.CertificateAuthority })
        {
            using var store = new X509Store(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            foreach (var certificate in store.Certificates)
                using (certificate) result.Add($"{name}:{certificate.Thumbprint}");
        }
        return result.Order(StringComparer.Ordinal).ToArray();
    }
}
