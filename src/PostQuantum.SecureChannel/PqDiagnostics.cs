using System.Diagnostics.Metrics;
using System.Diagnostics.Tracing;

namespace PostQuantum.SecureChannel;

/// <summary>
/// Observable signals emitted by PostQuantum.SecureChannel. Two equivalent surfaces are exposed:
/// an <see cref="EventSource"/> named <c>PostQuantum.SecureChannel</c> for ETW/EventPipe consumers
/// (dotnet-trace, dotnet-counters, PerfView), and a <see cref="Meter"/> of the same name for OpenTelemetry
/// or any <c>System.Diagnostics.Metrics</c> listener.
/// </summary>
/// <remarks>
/// <para>
/// All emissions are best-effort and side-effect-free for the protocol: an exception thrown by a
/// listener never propagates back through the channel. Counter values are monotonically increasing
/// over the process lifetime; reset them downstream.
/// </para>
/// <para>Listener wiring is described in <c>docs/observability.md</c>.</para>
/// </remarks>
public static class PqDiagnostics
{
    /// <summary>The name used by both the EventSource and the Meter.</summary>
    public const string Name = "PostQuantum.SecureChannel";

    /// <summary>The <see cref="System.Diagnostics.Metrics.Meter"/> instance. Subscribe with <c>MeterListener</c> or OpenTelemetry.</summary>
    public static readonly Meter Meter = new(Name, ThisAssemblyVersion);

    internal static readonly Counter<long> HandshakesStarted =
        Meter.CreateCounter<long>("pqsc.handshakes.started", description: "Number of handshakes initiated (client) or accepted (server).");

    internal static readonly Counter<long> HandshakesCompleted =
        Meter.CreateCounter<long>("pqsc.handshakes.completed", description: "Number of handshakes that produced a live session.");

    internal static readonly Counter<long> HandshakesFailed =
        Meter.CreateCounter<long>("pqsc.handshakes.failed", description: "Number of handshakes aborted by an authentication or protocol failure.");

    internal static readonly Counter<long> RecordsRejected =
        Meter.CreateCounter<long>("pqsc.records.rejected", description: "Decryption rejections: replay, reorder, tampered, or window-old.");

    internal static readonly Counter<long> KeyUpdatesSent =
        Meter.CreateCounter<long>("pqsc.key_updates.sent", description: "Send-direction ratchets performed locally.");

    internal static readonly Counter<long> KeyUpdatesReceived =
        Meter.CreateCounter<long>("pqsc.key_updates.received", description: "Receive-direction ratchets in response to a peer key update.");

    internal static readonly Counter<long> EpochsExhausted =
        Meter.CreateCounter<long>("pqsc.epochs.exhausted", description: "Sends rejected because the per-epoch record or byte cap was reached.");

    private static string ThisAssemblyVersion =>
        typeof(PqDiagnostics).Assembly.GetName().Version?.ToString() ?? "0.0.0";

    internal static void HandshakeStarted(PqRole role)
    {
        HandshakesStarted.Add(1, new KeyValuePair<string, object?>("role", role.ToString()));
        Source.HandshakeStarted(role);
    }

    internal static void HandshakeCompleted(PqRole role, bool resumed, bool mutual)
    {
        HandshakesCompleted.Add(1,
            new KeyValuePair<string, object?>("role", role.ToString()),
            new KeyValuePair<string, object?>("resumed", resumed),
            new KeyValuePair<string, object?>("mutual", mutual));
        Source.HandshakeCompleted(role, resumed, mutual);
    }

    internal static void HandshakeFailed(PqRole role, string reason)
    {
        HandshakesFailed.Add(1,
            new KeyValuePair<string, object?>("role", role.ToString()),
            new KeyValuePair<string, object?>("reason", reason));
        Source.HandshakeFailed(role, reason);
    }

    internal static void RecordRejected(PqRole role, string reason)
    {
        RecordsRejected.Add(1,
            new KeyValuePair<string, object?>("role", role.ToString()),
            new KeyValuePair<string, object?>("reason", reason));
        Source.RecordRejected(role, reason);
    }

    internal static void KeyUpdated(PqRole role, bool isReceive, uint newEpoch)
    {
        if (isReceive)
        {
            KeyUpdatesReceived.Add(1, new KeyValuePair<string, object?>("role", role.ToString()));
            Source.KeyUpdateReceived(role, (int)newEpoch);
        }
        else
        {
            KeyUpdatesSent.Add(1, new KeyValuePair<string, object?>("role", role.ToString()));
            Source.KeyUpdateSent(role, (int)newEpoch);
        }
    }

    internal static void EpochExhausted(PqRole role, bool isReceive, bool recordCap)
    {
        EpochsExhausted.Add(1,
            new KeyValuePair<string, object?>("role", role.ToString()),
            new KeyValuePair<string, object?>("direction", isReceive ? "receive" : "send"),
            new KeyValuePair<string, object?>("limit", recordCap ? "records" : "bytes"));
        Source.EpochExhausted(role, isReceive, recordCap);
    }

    private static PqEventSource Source => PqEventSource.Log;
}

/// <summary>
/// The ETW/EventPipe event source for PostQuantum.SecureChannel. Enable via
/// <c>dotnet-trace collect --providers PostQuantum.SecureChannel</c>.
/// </summary>
[EventSource(Name = PqDiagnostics.Name)]
internal sealed class PqEventSource : EventSource
{
    internal static readonly PqEventSource Log = new();

    private PqEventSource() { }

    [Event(1, Level = EventLevel.Informational, Message = "Handshake started (role={0}).")]
    internal void HandshakeStarted(PqRole role)
    {
        if (IsEnabled())
        {
            WriteEvent(1, (int)role);
        }
    }

    [Event(2, Level = EventLevel.Informational, Message = "Handshake completed (role={0}, resumed={1}, mutual={2}).")]
    internal void HandshakeCompleted(PqRole role, bool resumed, bool mutual)
    {
        if (IsEnabled())
        {
            WriteEvent(2, (int)role, resumed ? 1 : 0, mutual ? 1 : 0);
        }
    }

    [Event(3, Level = EventLevel.Warning, Message = "Handshake failed (role={0}, reason={1}).")]
    internal void HandshakeFailed(PqRole role, string reason)
    {
        if (IsEnabled())
        {
            WriteEvent(3, (int)role, reason ?? string.Empty);
        }
    }

    [Event(4, Level = EventLevel.Warning, Message = "Record rejected (role={0}, reason={1}).")]
    internal void RecordRejected(PqRole role, string reason)
    {
        if (IsEnabled())
        {
            WriteEvent(4, (int)role, reason ?? string.Empty);
        }
    }

    [Event(5, Level = EventLevel.Informational, Message = "Key update sent (role={0}, newSendEpoch={1}).")]
    internal void KeyUpdateSent(PqRole role, int newEpoch)
    {
        if (IsEnabled())
        {
            WriteEvent(5, (int)role, newEpoch);
        }
    }

    [Event(6, Level = EventLevel.Informational, Message = "Key update received (role={0}, newReceiveEpoch={1}).")]
    internal void KeyUpdateReceived(PqRole role, int newEpoch)
    {
        if (IsEnabled())
        {
            WriteEvent(6, (int)role, newEpoch);
        }
    }

    [Event(7, Level = EventLevel.Error, Message = "Epoch exhausted (role={0}, receive={1}, recordCap={2}).")]
    internal void EpochExhausted(PqRole role, bool isReceive, bool recordCap)
    {
        if (IsEnabled())
        {
            WriteEvent(7, (int)role, isReceive ? 1 : 0, recordCap ? 1 : 0);
        }
    }
}
