using System.Text;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>Protocol-wide constants and domain-separation labels.</summary>
internal static class PqProtocol
{
    /// <summary>The message-format version stamped on every handshake message and record.</summary>
    internal const byte Version = 1;

    /// <summary>
    /// Protocol versions this build can speak, highest first. Used for handshake version negotiation.
    /// The X-Wing component tracks <c>draft-connolly-cfrg-xwing-kem</c>; see <c>docs/protocol.md</c>.
    /// </summary>
    internal static readonly byte[] SupportedVersions = [1];

    internal const int RandomSize = 32;

    // Record content types (TLS-style numbering for familiarity).
    internal const byte RecordApplicationData = 0x17;
    internal const byte RecordKeyUpdate = 0x18;

    // Handshake authentication contexts.
    internal static readonly byte[] ServerAuthContext = Label("pqsc/v1 server-auth");
    internal static readonly byte[] ClientAuthContext = Label("pqsc/v1 client-auth");

    // Key-schedule labels.
    internal const string MasterInfo = "pqsc/v1 master";
    internal const string ClientToServerTrafficInfo = "pqsc/v1 c2s traffic";
    internal const string ServerToClientTrafficInfo = "pqsc/v1 s2c traffic";
    internal const string ClientFinishedInfo = "pqsc/v1 client finished";
    internal const string ServerFinishedInfo = "pqsc/v1 server finished";
    internal const string ResumptionInfo = "pqsc/v1 resumption";

    // Per-direction traffic-secret labels.
    internal const string TrafficKeyInfo = "pqsc/v1 key";
    internal const string TrafficIvInfo = "pqsc/v1 iv";
    internal const string KeyUpdateInfo = "pqsc/v1 key update";

    private static byte[] Label(string text) => Encoding.ASCII.GetBytes(text);

    /// <summary>Picks the highest version supported by both peers, or returns 0 if there is no overlap.</summary>
    internal static byte NegotiateVersion(ReadOnlySpan<byte> clientSupported)
    {
        byte best = 0;
        foreach (var ours in SupportedVersions)
        {
            foreach (var theirs in clientSupported)
            {
                if (ours == theirs && ours > best)
                {
                    best = ours;
                }
            }
        }

        return best;
    }
}
