using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Regression-locks the Step-0 analysis of external-review Finding 1: the wrap-around path through
/// <see cref="AntiReplayWindow"/> correctly REJECTS the suspected scenarios. These tests would have
/// failed in the form the reviewer claimed (silent acceptance of a stale/duplicate packet) — they
/// pass today because <c>IsAcceptable</c> handles the relevant cases correctly, and they document
/// that fact so a future refactor cannot silently introduce the bug.
/// </summary>
public class AntiReplayWrapTests
{
    [Fact]
    public void WrapAdjacent_HighestNearMax_ZeroRejected()
    {
        // After Commit(ulong.MaxValue), arrival of sequence 0 must be rejected:
        // sequence > _highest is false, distance = MaxValue, which exceeds any window.
        var window = new AntiReplayWindow(64);
        window.Commit(ulong.MaxValue);

        Assert.False(window.IsAcceptable(0));
        Assert.False(window.IsAcceptable(1));
        Assert.False(window.IsAcceptable(ulong.MaxValue - 100));
        Assert.False(window.IsAcceptable(ulong.MaxValue)); // replay of highest
    }

    [Fact]
    public void WrapAdjacent_HighestNearMax_InWindowAccepted()
    {
        // Sequences just below MaxValue and inside the window must still be acceptable.
        var window = new AntiReplayWindow(64);
        window.Commit(ulong.MaxValue);

        Assert.True(window.IsAcceptable(ulong.MaxValue - 1));    // distance 1
        Assert.True(window.IsAcceptable(ulong.MaxValue - 63));   // distance 63
        Assert.False(window.IsAcceptable(ulong.MaxValue - 64));  // distance 64 == window
    }

    [Fact]
    public void HugeForwardJump_ResetsWindowAndAccepts()
    {
        // A massive forward jump (e.g., adversarial sequence) advances _highest and clears the window;
        // the new highest is itself a replay candidate, while sequences just below it are unseen.
        var window = new AntiReplayWindow(64);
        window.Commit(5);
        window.Commit(ulong.MaxValue / 2);

        Assert.False(window.IsAcceptable(ulong.MaxValue / 2));        // replay of new highest
        Assert.True(window.IsAcceptable(ulong.MaxValue / 2 - 30));    // in-window, unseen
        Assert.False(window.IsAcceptable(5));                          // far below new window
        Assert.False(window.IsAcceptable(0));                          // far below new window
    }

    [Fact]
    public void HugeForwardJump_DoesNotUnderflowDistance()
    {
        // The previous-state distance computation (_highest - sequence) could in principle underflow
        // if a sequence > _highest were ever forwarded into it; the early-return on sequence > _highest
        // prevents that. This test pins the invariant.
        var window = new AntiReplayWindow(128);
        window.Commit(100);

        // sequence = ulong.MaxValue is greater than _highest = 100, so IsAcceptable short-circuits
        // before computing distance and returns true (would advance the window if committed).
        Assert.True(window.IsAcceptable(ulong.MaxValue));
    }

    [Fact]
    public void SparseAdversarialFar_DoesNotAcceptReplays()
    {
        // A scenario styled after the "long-lived adversarial peer" claim: sparse, far-apart commits
        // should advance the window each time; nothing previously committed should re-accept.
        var window = new AntiReplayWindow(64);
        ulong[] sequence = [10, 1_000_000, 1UL << 40, (1UL << 60) + 5, ulong.MaxValue - 64];
        foreach (var s in sequence)
        {
            Assert.True(window.IsAcceptable(s), $"first acceptance failed for {s}");
            window.Commit(s);
            Assert.False(window.IsAcceptable(s), $"replay should be rejected for {s}");
        }
    }
}
