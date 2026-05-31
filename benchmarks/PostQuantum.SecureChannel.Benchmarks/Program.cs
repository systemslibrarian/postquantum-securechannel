using BenchmarkDotNet.Running;
using PostQuantum.SecureChannel.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(XWingBenchmarks).Assembly).Run(args);
