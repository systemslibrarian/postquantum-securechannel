using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Direct exercises of the bitmap-backed <see cref="AntiReplayWindow"/>: small windows, large
/// sequence jumps, and adversarial sequences that would have caused unbounded HashSet growth in the
/// previous implementation.
/// </summary>
public class AntiReplayBitmapTests
{
    [Fact]
    public void First_AlwaysAccepted()
    {
        var window = new AntiReplayWindow(64);
        Assert.True(window.IsAcceptable(0));
        window.Commit(0);
        Assert.False(window.IsAcceptable(0)); // replay
    }

    [Fact]
    public void OutOfOrder_WithinWindow_IsAccepted()
    {
        var window = new AntiReplayWindow(64);
        window.Commit(10);
        Assert.True(window.IsAcceptable(5));
        window.Commit(5);
        Assert.False(window.IsAcceptable(5)); // replay
        Assert.False(window.IsAcceptable(10));
    }

    [Fact]
    public void TooOld_Rejected()
    {
        var window = new AntiReplayWindow(64);
        window.Commit(100);
        Assert.False(window.IsAcceptable(35)); // distance 65 >= window 64
        Assert.True(window.IsAcceptable(37));  // distance 63 < window 64
    }

    [Fact]
    public void AdvancingFar_ShiftsAndForgets()
    {
        var window = new AntiReplayWindow(64);
        window.Commit(0);
        window.Commit(5);

        // Jump well past the window.
        window.Commit(10_000);

        // The old sequences are forgotten and the bitmap is clear except for 10_000.
        Assert.False(window.IsAcceptable(10_000));      // replay of current highest
        Assert.False(window.IsAcceptable(9_900));       // outside window
        Assert.True(window.IsAcceptable(9_990));        // distance 10 < window 64, never seen
    }

    [Fact]
    public void AdversarialSparse_DoesNotAllocate()
    {
        // The HashSet-backed implementation would grow indefinitely as a peer sent sparse sequences.
        // The bitmap is allocated once at construction; this test just verifies many sparse commits
        // remain functional.
        var window = new AntiReplayWindow(128);
        for (ulong seq = 0; seq < 10_000; seq += 7)
        {
            Assert.True(window.IsAcceptable(seq), $"seq={seq}");
            window.Commit(seq);
        }

        // The most recent committed sequence should now be the highest, and replaying it is rejected.
        Assert.False(window.IsAcceptable(9_996));
    }

    [Fact]
    public void NonAlignedWindowSize_StillBehavesCorrectly()
    {
        // 100 is not a multiple of 64; the bitmap rounds up to 128 bits.
        var window = new AntiReplayWindow(100);
        window.Commit(0);
        window.Commit(50);
        window.Commit(99);

        Assert.False(window.IsAcceptable(0));   // replay (within window)
        Assert.False(window.IsAcceptable(50));  // replay
        Assert.False(window.IsAcceptable(99));  // replay (current highest)

        // Advance past so that 99 falls out of the new window.
        window.Commit(200);
        Assert.False(window.IsAcceptable(99));  // now too old (distance 101 >= 100)
        Assert.True(window.IsAcceptable(101));  // distance 99 < 100
    }

    [Fact]
    public void ExactlyAtWindowBoundary_IsRejected()
    {
        var window = new AntiReplayWindow(64);
        window.Commit(64);

        Assert.False(window.IsAcceptable(0));   // distance 64 >= window 64
        Assert.True(window.IsAcceptable(1));    // distance 63 < window 64
    }

    /// <summary>
    /// Finding 1e (external review): Commit must refuse to record a sequence that IsAcceptable would
    /// have rejected, so a future caller forgetting the gate cannot silently mis-record a replay or
    /// out-of-window sequence.
    /// </summary>
    [Fact]
    public void Commit_WithoutIsAcceptableApproval_Throws()
    {
        var window = new AntiReplayWindow(64);
        window.Commit(100);

        // Replaying the highest sequence: IsAcceptable returns false, so Commit must refuse.
        Assert.False(window.IsAcceptable(100));
        Assert.Throws<InvalidOperationException>(() => window.Commit(100));

        // A sequence well outside the window: same enforcement.
        Assert.False(window.IsAcceptable(0));
        Assert.Throws<InvalidOperationException>(() => window.Commit(0));
    }
}
