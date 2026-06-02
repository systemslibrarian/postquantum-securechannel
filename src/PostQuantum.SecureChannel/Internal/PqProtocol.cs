using System.Text;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>Protocol-wide constants and domain-separation labels.</summary>
/// <remarks>
/// <para>
/// <b>Wire-format version 2.</b> This version landed inside the <c>0.3.0-preview.1</c> window as the
/// remediation for an external review of the HKDF info construction and transcript framing. It is
/// <b>not</b> wire-compatible with version 1: every derived key changes (HKDF info is now a TLS 1.3
/// <c>HkdfLabel</c> structure with explicit length framing), and the transcript is now length-prefixed
/// per fragment. Handshakes between a v1 peer and a v2 peer fail cleanly at version negotiation.
/// </para>
/// </remarks>
internal static class PqProtocol
{
    /// <summary>The message-format version stamped on every handshake message and record.</summary>
    internal const byte Version = 2;

    /// <summary>
    /// Protocol versions this build can speak, highest first. Used for handshake version negotiation.
    /// The X-Wing component tracks <c>draft-connolly-cfrg-xwing-kem</c>; see <c>docs/protocol.md</c>.
    /// </summary>
    internal static readonly byte[] SupportedVersions = [2];

    internal const int RandomSize = 32;

    // Record content types (TLS-style numbering for familiarity).
    internal const byte RecordApplicationData = 0x17;
    internal const byte RecordKeyUpdate = 0x18;

    // Handshake authentication contexts.
    internal static readonly byte[] ServerAuthContext = Label("pqsc/v2 server-auth");
    internal static readonly byte[] ClientAuthContext = Label("pqsc/v2 client-auth");

    // Key-schedule labels.
    internal const string MasterInfo = "pqsc/v2 master";
    internal const string ClientToServerTrafficInfo = "pqsc/v2 c2s traffic";
    internal const string ServerToClientTrafficInfo = "pqsc/v2 s2c traffic";
    internal const string ClientFinishedInfo = "pqsc/v2 client finished";
    internal const string ServerFinishedInfo = "pqsc/v2 server finished";
    internal const string ResumptionInfo = "pqsc/v2 resumption";

    // Per-direction traffic-secret labels.
    internal const string TrafficKeyInfo = "pqsc/v2 key";
    internal const string TrafficIvInfo = "pqsc/v2 iv";
    internal const string KeyUpdateInfo = "pqsc/v2 key update";

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
