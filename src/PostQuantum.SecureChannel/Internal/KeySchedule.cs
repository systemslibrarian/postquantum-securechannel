using System.Security.Cryptography;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>
/// The HKDF-SHA256 key schedule. Turns the raw X-Wing shared secret &#8212; bound to both endpoints'
/// nonces, the handshake transcript, and an optional resumption pre-shared secret &#8212; into
/// per-direction traffic secrets, Finished-MAC keys, and an exported resumption secret.
/// </summary>
internal sealed class KeySchedule
{
    private const int SecretSize = 32;

    internal byte[] ClientToServerTrafficSecret { get; }
    internal byte[] ServerToClientTrafficSecret { get; }
    internal byte[] ClientFinishedKey { get; }
    internal byte[] ServerFinishedKey { get; }
    internal byte[] ResumptionSecret { get; }

    private KeySchedule(byte[] c2s, byte[] s2c, byte[] clientFinished, byte[] serverFinished, byte[] resumption)
    {
        ClientToServerTrafficSecret = c2s;
        ServerToClientTrafficSecret = s2c;
        ClientFinishedKey = clientFinished;
        ServerFinishedKey = serverFinished;
        ResumptionSecret = resumption;
    }

    /// <summary>
    /// Derives the schedule.
    /// <para>salt = clientRandom ‖ serverRandom ‖ resumptionPsk; PRK = HKDF-Extract(salt, sharedSecret).</para>
    /// <para>master = HKDF-Expand(PRK, "master" ‖ transcriptHash); all secrets expand from master.</para>
    /// </summary>
    internal static KeySchedule Derive(
        ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> clientRandom, ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> transcriptHash, ReadOnlySpan<byte> resumptionPsk = default)
    {
        Span<byte> salt = stackalloc byte[clientRandom.Length + serverRandom.Length + resumptionPsk.Length];
        clientRandom.CopyTo(salt);
        serverRandom.CopyTo(salt[clientRandom.Length..]);
        resumptionPsk.CopyTo(salt[(clientRandom.Length + serverRandom.Length)..]);

        var prk = Hkdf.Extract(salt, sharedSecret);
        var master = Hkdf.Expand(prk, PqProtocol.MasterInfo, SecretSize, transcriptHash);
        try
        {
            return new KeySchedule(
                Hkdf.Expand(master, PqProtocol.ClientToServerTrafficInfo, SecretSize),
                Hkdf.Expand(master, PqProtocol.ServerToClientTrafficInfo, SecretSize),
                Hkdf.Expand(master, PqProtocol.ClientFinishedInfo, SecretSize),
                Hkdf.Expand(master, PqProtocol.ServerFinishedInfo, SecretSize),
                Hkdf.Expand(master, PqProtocol.ResumptionInfo, SecretSize));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(master);
            CryptographicOperations.ZeroMemory(prk);
        }
    }
}
