namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// A sliding-window anti-replay filter in the style of IPsec (RFC 6479) and DTLS. Tracks the highest
/// sequence number seen and a fixed-size bitmap of the window below it, accepting each sequence number
/// at most once.
/// </summary>
/// <remarks>
/// The bitmap is allocated once at construction with a size proportional to the configured window
/// (rounded up to the next 64 bits). A peer therefore cannot influence the receiver's memory footprint
/// by sending crafted sequence numbers — every check and commit is O(1) and allocation-free.
/// </remarks>
internal sealed class AntiReplayWindow
{
    private const int BitsPerWord = 64;

    private readonly int _windowSize;
    private readonly ulong[] _bitmap;
    private ulong _highest;
    private bool _any;

    internal AntiReplayWindow(int windowSize)
    {
        _windowSize = windowSize;
        _bitmap = new ulong[(windowSize + BitsPerWord - 1) / BitsPerWord];
    }

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

        ulong distance = _highest - sequence;
        if (distance >= (ulong)_windowSize)
        {
            return false; // too old: below the window
        }

        return !GetBit(distance);
    }

    /// <summary>Records <paramref name="sequence"/> as consumed, advancing and zeroing the window as needed.</summary>
    internal void Commit(ulong sequence)
    {
        if (!_any)
        {
            _highest = sequence;
            _any = true;
            SetBit(0);
            return;
        }

        if (sequence > _highest)
        {
            ulong shift = sequence - _highest;
            ShiftLeft(shift);
            _highest = sequence;
            SetBit(0);
        }
        else
        {
            ulong distance = _highest - sequence;
            // IsAcceptable already vetted distance < windowSize.
            SetBit(distance);
        }
    }

    private bool GetBit(ulong distance)
    {
        int word = (int)(distance / BitsPerWord);
        int bit = (int)(distance % BitsPerWord);
        return (_bitmap[word] & (1UL << bit)) != 0UL;
    }

    private void SetBit(ulong distance)
    {
        int word = (int)(distance / BitsPerWord);
        int bit = (int)(distance % BitsPerWord);
        _bitmap[word] |= 1UL << bit;
    }

    /// <summary>Shifts the bitmap left by <paramref name="shift"/> bits (older sequences fall off the end).</summary>
    private void ShiftLeft(ulong shift)
    {
        if (shift >= (ulong)_windowSize)
        {
            Array.Clear(_bitmap);
            return;
        }

        int wordShift = (int)(shift / BitsPerWord);
        int bitShift = (int)(shift % BitsPerWord);

        if (wordShift > 0)
        {
            for (int i = _bitmap.Length - 1; i >= 0; i--)
            {
                int src = i - wordShift;
                _bitmap[i] = src >= 0 ? _bitmap[src] : 0UL;
            }
        }

        if (bitShift > 0)
        {
            ulong carry = 0UL;
            for (int i = 0; i < _bitmap.Length; i++)
            {
                ulong current = _bitmap[i];
                _bitmap[i] = (current << bitShift) | carry;
                carry = current >> (BitsPerWord - bitShift);
            }
        }
    }
}
