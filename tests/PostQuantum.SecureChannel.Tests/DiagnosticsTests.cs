using System.Diagnostics.Metrics;
using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Sanity-checks that <see cref="PqDiagnostics"/> emits counters for the expected events. A
/// <see cref="MeterListener"/> captures emissions; the actual signal shapes are validated
/// independently by integration consumers (OpenTelemetry, dotnet-counters).
/// </summary>
public class DiagnosticsTests
{
    private sealed class Capture : IDisposable
    {
        private readonly MeterListener _listener;
        private readonly Dictionary<string, long> _counts = new();
        private readonly object _lock = new();

        internal Capture()
        {
            _listener = new MeterListener();
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == PqDiagnostics.Name)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((instrument, measurement, _, _) =>
            {
                lock (_lock)
                {
                    _counts.TryGetValue(instrument.Name, out var current);
                    _counts[instrument.Name] = current + measurement;
                }
            });
            _listener.Start();
        }

        internal long Get(string instrument)
        {
            lock (_lock)
            {
                return _counts.TryGetValue(instrument, out var v) ? v : 0;
            }
        }

        public void Dispose() => _listener.Dispose();
    }

    [Fact]
    public void HandshakeSuccess_EmitsStartedAndCompleted()
    {
        using var capture = new Capture();
        using var serverIdentity = PqIdentity.Create();

        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        _ = server.ProcessClientFinished(result.ClientFinished);

        Assert.True(capture.Get("pqsc.handshakes.started") >= 2, "expected both sides to emit started");
        Assert.True(capture.Get("pqsc.handshakes.completed") >= 2, "expected both sides to emit completed");
    }

    [Fact]
    public void HandshakeFailure_EmitsFailedCounter()
    {
        using var capture = new Capture();
        using var realServer = PqIdentity.Create();
        using var imposter = PqIdentity.Create();

        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = imposter.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = realServer });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());

        Assert.Throws<PqAuthenticationException>(() => client.ProcessServerHello(serverHello));
        Assert.True(capture.Get("pqsc.handshakes.failed") >= 1);
    }

    [Fact]
    public void RecordReplay_EmitsRejectionCounter()
    {
        using var capture = new Capture();
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);

        var record = result.Session.Encrypt(Encoding.UTF8.GetBytes("once"));
        _ = serverSession.Decrypt(record);
        Assert.Throws<PqDecryptionException>(() => serverSession.Decrypt(record));

        Assert.True(capture.Get("pqsc.records.rejected") >= 1);
    }

    [Fact]
    public void KeyUpdate_EmitsSentAndReceivedCounters()
    {
        using var capture = new Capture();
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);

        var update = result.Session.UpdateSendKey();
        _ = serverSession.Open(update);

        Assert.True(capture.Get("pqsc.key_updates.sent") >= 1);
        Assert.True(capture.Get("pqsc.key_updates.received") >= 1);
    }
}
