using BenchmarkDotNet.Attributes;
using PostQuantum.SecureChannel.Cryptography;

namespace PostQuantum.SecureChannel.Benchmarks;

[MemoryDiagnoser]
public class XWingBenchmarks
{
    private XWingKeyPair _keyPair = null!;
    private byte[] _ciphertext = null!;

    [GlobalSetup]
    public void Setup()
    {
        _keyPair = XWing.GenerateKeyPair();
        (_ciphertext, _) = XWing.Encapsulate(_keyPair.PublicKey);
    }

    [Benchmark]
    public XWingKeyPair GenerateKeyPair() => XWing.GenerateKeyPair();

    [Benchmark]
    public byte[] Encapsulate()
    {
        var (ct, _) = XWing.Encapsulate(_keyPair.PublicKey);
        return ct;
    }

    [Benchmark]
    public byte[] Decapsulate() => _keyPair.Decapsulate(_ciphertext);
}
