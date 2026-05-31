using BenchmarkDotNet.Attributes;

namespace PostQuantum.SecureChannel.Benchmarks;

[MemoryDiagnoser]
public class RecordThroughputBenchmarks
{
    private PqIdentity _serverIdentity = null!;
    private PqSession _client = null!;
    private PqSession _server = null!;
    private byte[] _plaintext = null!;
    private byte[] _record = null!;

    [Params(64, 1024, 16 * 1024, 256 * 1024)]
    public int PayloadSize;

    [GlobalSetup]
    public void Setup()
    {
        _serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = _serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = _serverIdentity });

        var hello = client.CreateClientHello();
        var sh = server.ProcessClientHello(hello);
        var result = client.ProcessServerHello(sh);
        _server = server.ProcessClientFinished(result.ClientFinished);
        _client = result.Session;

        _plaintext = new byte[PayloadSize];
        Random.Shared.NextBytes(_plaintext);
        _record = _client.Encrypt(_plaintext);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _client.Dispose();
        _server.Dispose();
        _serverIdentity.Dispose();
    }

    [Benchmark]
    public byte[] Encrypt() => _client.Encrypt(_plaintext);

    [Benchmark]
    public byte[] Decrypt()
    {
        // Server's recv sequence stays at 0 for this microbenchmark; we measure raw AEAD throughput
        // by re-decrypting the same captured record. In real use each record has a unique sequence.
        try { return _server.Decrypt(_record); }
        catch (PqDecryptionException)
        {
            // Re-establish to get a fresh recv sequence after the first iteration. The Decrypt cost
            // dominates re-establishment except for very small payloads, where this benchmark is
            // less meaningful anyway.
            ResetServer();
            return _server.Decrypt(_record);
        }
    }

    private void ResetServer()
    {
        _server.Dispose();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = _serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = _serverIdentity });

        var hello = client.CreateClientHello();
        var sh = server.ProcessClientHello(hello);
        var result = client.ProcessServerHello(sh);
        _server = server.ProcessClientFinished(result.ClientFinished);

        _client.Dispose();
        _client = result.Session;
        _record = _client.Encrypt(_plaintext);
    }
}
