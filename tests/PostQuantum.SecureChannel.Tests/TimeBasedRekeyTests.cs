using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Covers <see cref="PqKeyUpdatePolicy.MaxAge"/> time-based auto-rekey: the send epoch's wall-clock age
/// trips <see cref="PqSession.NeedsKeyUpdate"/>, a rekey resets the epoch clock, and the age term is
/// evaluated against the injectable <see cref="PqSessionOptions.TimeProvider"/> so it is deterministic.
/// </summary>
public class TimeBasedRekeyTests
{
    /// <summary>A hand-driven <see cref="TimeProvider"/> whose timestamp only advances when told to.</summary>
    private sealed class FakeTimeProvider : TimeProvider
    {
        private long _ticks;
        public override long GetTimestamp() => _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch + TimeSpan.FromTicks(_ticks);
        public void Advance(TimeSpan by) => _ticks += by.Ticks;
    }

    private static PqSession EstablishClient(PqSessionOptions sessionOptions)
    {
        using var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions
        {
            ServerIdentity = serverIdentity.PublicKey,
            SessionOptions = sessionOptions,
        });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var hello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(hello);
        server.ProcessClientFinished(result.ClientFinished);
        return result.Session;
    }

    [Fact]
    public void EpochAge_TripsNeedsKeyUpdate_AndRekeyResetsTheClock()
    {
        var clock = new FakeTimeProvider();
        using var session = EstablishClient(new PqSessionOptions
        {
            KeyUpdatePolicy = new PqKeyUpdatePolicy { MaxAge = TimeSpan.FromMinutes(1) },
            TimeProvider = clock,
        });

        Assert.False(session.NeedsKeyUpdate);           // fresh epoch, age 0

        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.False(session.NeedsKeyUpdate);           // still under the 1-minute bound

        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(session.NeedsKeyUpdate);            // 61s > 60s

        session.UpdateSendKey();                        // ratchet resets the epoch clock
        Assert.False(session.NeedsKeyUpdate);

        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.True(session.NeedsKeyUpdate);            // the new epoch has now aged out too
    }

    [Fact]
    public void MaxAge_Unset_NeverTripsOnTimeAlone()
    {
        var clock = new FakeTimeProvider();
        using var session = EstablishClient(new PqSessionOptions
        {
            KeyUpdatePolicy = PqKeyUpdatePolicy.Disabled, // no MaxAge
            TimeProvider = clock,
        });

        clock.Advance(TimeSpan.FromDays(365));
        Assert.False(session.NeedsKeyUpdate);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void MaxAge_MustBePositive(int seconds)
    {
        var policy = new PqKeyUpdatePolicy { MaxAge = TimeSpan.FromSeconds(seconds) };
        Assert.Throws<ArgumentOutOfRangeException>(() => policy.Validate());
    }

    [Fact]
    public void RecommendedPolicy_IncludesAnAgeBound()
    {
        Assert.NotNull(PqKeyUpdatePolicy.Recommended.MaxAge);
        Assert.True(PqKeyUpdatePolicy.Recommended.MaxAge > TimeSpan.Zero);
    }
}
