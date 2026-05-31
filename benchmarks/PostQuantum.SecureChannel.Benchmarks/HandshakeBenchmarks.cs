using BenchmarkDotNet.Attributes;

namespace PostQuantum.SecureChannel.Benchmarks;

[MemoryDiagnoser]
public class HandshakeBenchmarks
{
    private PqIdentity _serverIdentity = null!;
    private PqIdentityPublicKey _pinned = null!;

    [GlobalSetup]
    public void Setup()
    {
        _serverIdentity = PqIdentity.Create();
        _pinned = _serverIdentity.PublicKey;
    }

    [GlobalCleanup]
    public void Cleanup() => _serverIdentity.Dispose();

    [Benchmark]
    public PqSession FullHandshake()
    {
        using var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = _pinned });
        using var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = _serverIdentity });

        var hello = client.CreateClientHello();
        var sh = server.ProcessClientHello(hello);
        var result = client.ProcessServerHello(sh);
        var session = server.ProcessClientFinished(result.ClientFinished);
        result.Session.Dispose();
        return session;
    }
}
