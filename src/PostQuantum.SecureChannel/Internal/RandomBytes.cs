using System.Security.Cryptography;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// Centralized access to the platform CSPRNG. Everything in this library that needs randomness
/// goes through here so the source is auditable in one place.
/// </summary>
internal static class RandomBytes
{
    internal static void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);

    internal static byte[] Create(int length)
    {
        var buffer = new byte[length];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }
}
