# Benchmarks

Reproducible microbenchmarks for the hot paths of PostQuantum.SecureChannel: X-Wing key agreement,
the full handshake, and AES-GCM record throughput across payload sizes.

```bash
# Run everything (long; use BenchmarkDotNet's filters for subsets):
dotnet run --project benchmarks/PostQuantum.SecureChannel.Benchmarks -c Release

# A single class:
dotnet run --project benchmarks/PostQuantum.SecureChannel.Benchmarks -c Release -- \
    --filter "*HandshakeBenchmarks*"

# A single payload-size scan:
dotnet run --project benchmarks/PostQuantum.SecureChannel.Benchmarks -c Release -- \
    --filter "*RecordThroughputBenchmarks*"
```

Numbers depend heavily on hardware; publish your own from the target deployment shape. The
benchmarks are deliberately minimal to keep them easy to re-run before each release.
