namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// A sliding-window anti-replay filter in the style of IPsec (RFC 6479) and DTLS. Tracks the highest
/// sequence number seen and a bitmap of the window below it, accepting each sequence number at most once.
/// </summary>
internal sealed class AntiReplayWindow
{
    private readonly int _windowSize;
    private readonly HashSet<ulong> _seen = new();
    private ulong _highest;
    private bool _any;

    internal AntiReplayWindow(int windowSize) => _windowSize = windowSize;

    /// <summary>Returns <see langword="true"/> if <paramref name="sequence"/> is fresh and acceptable.</summary>
    internal bool IsAcceptable(ulong sequence)
    {
        if (!_any)
        {
            return true;
        }

        if (sequence > _highest)
        {
            return true; // advances the window
        }

        if (_highest - sequence >= (ulong)_windowSize)
        {
            return false; // too old: below the window
        }

        return !_seen.Contains(sequence); // within the window and not yet seen
    }

    /// <summary>Records <paramref name="sequence"/> as consumed, advancing and pruning the window as needed.</summary>
    internal void Commit(ulong sequence)
    {
        _any = true;
        _seen.Add(sequence);

        if (sequence > _highest)
        {
            _highest = sequence;
        }

        // Drop entries that have fallen out of the window; they can never be accepted again anyway.
        ulong cutoff = _highest >= (ulong)_windowSize ? _highest - (ulong)_windowSize : 0;
        _seen.RemoveWhere(s => s < cutoff);
    }
}
