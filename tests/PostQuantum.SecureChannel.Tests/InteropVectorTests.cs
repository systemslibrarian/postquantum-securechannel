using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Generates and self-verifies the language-neutral interop vectors under
/// <c>docs/interop-vectors/</c>. These vectors pin the composition surfaces a second implementation
/// (in any language) must reproduce byte-for-byte to interoperate: the TLS 1.3-style HKDF
/// <c>info</c> construction, the length-prefixed transcript hash, the full HKDF-SHA256 key schedule,
/// and the per-direction record-layer key/IV/nonce/ratchet derivation.
///
/// <para>
/// The X-Wing KEM itself is validated separately against the published IETF KAT vectors
/// (<see cref="XWingTests"/>); these vectors cover the glue this repository owns, which no external
/// KAT exercises. The test bootstraps the file on first run and thereafter fails if the library's
/// output drifts from the checked-in vectors — so the published artifact can never silently diverge
/// from the code.
/// </para>
/// </summary>
public class InteropVectorTests
{
    // Deterministic, human-recognizable inputs (shared shape with KeyScheduleKatTests).
    private static readonly byte[] SharedSecret = Pattern(0xAA, 32);
    private static readonly byte[] ClientRandom = Pattern(0x10, 32);
    private static readonly byte[] ServerRandom = Pattern(0x20, 32);
    private static readonly byte[] TranscriptHash = Pattern(0x30, 32);
    private static readonly byte[] ResumptionPsk = Pattern(0x42, 32);

    [Fact]
    public void InteropVectors_MatchCheckedInArtifact()
    {
        string actual = Render();

        string path = Path.Combine(RepoRoot(), "docs", "interop-vectors", "composition-vectors.v2.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        if (!File.Exists(path))
        {
            File.WriteAllText(path, actual);
            return; // bootstrap
        }

        string approved = File.ReadAllText(path).Replace("\r\n", "\n");
        Assert.Equal(approved, actual.Replace("\r\n", "\n"));
    }

    private static string Render()
    {
        var scheduleNoPsk = KeySchedule.Derive(SharedSecret, ClientRandom, ServerRandom, TranscriptHash);
        var schedulePsk = KeySchedule.Derive(SharedSecret, ClientRandom, ServerRandom, TranscriptHash, ResumptionPsk);

        // Record-layer keying for the client→server direction under its epoch-0 traffic secret.
        var c2s = scheduleNoPsk.ClientToServerTrafficSecret;
        var trafficKey = Hkdf.Expand(c2s, PqProtocol.TrafficKeyInfo, 32);
        var ivPrefix = Hkdf.Expand(c2s, PqProtocol.TrafficIvInfo, 4);
        var ratcheted = Hkdf.Expand(c2s, PqProtocol.KeyUpdateInfo, 32);
        var nonceForSeq5 = NonceFor(ivPrefix, 5);

        var root = new JsonObject
        {
            ["description"] =
                "Language-neutral interop vectors for PostQuantum.SecureChannel protocol version 2. "
                + "A conformant implementation in any language MUST reproduce every 'output' below from "
                + "the given 'input'. Covers the composition surfaces this library owns; the X-Wing KEM "
                + "is validated separately against the published IETF KAT vectors.",
            ["protocolVersion"] = 2,
            ["specification"] = "docs/protocol.md",
            ["primitives"] = new JsonObject
            {
                ["kdf"] = "HKDF-SHA256",
                ["transcriptHash"] = "SHA-256",
                ["finishedMac"] = "HMAC-SHA256",
                ["recordAead"] = "AES-256-GCM (128-bit tag, 96-bit nonce)",
            },

            // 1. HKDF info construction (TLS 1.3 HkdfLabel): uint16 length | uint8 label_len | label | uint8 ctx_len | ctx.
            ["hkdfInfo"] = new JsonObject
            {
                ["construction"] = "uint16_BE(length) || uint8(label_len) || label_ascii || uint8(context_len) || context",
                ["examples"] = new JsonArray
                {
                    HkdfInfoExample(PqProtocol.MasterInfo, 32, TranscriptHash),
                    HkdfInfoExample(PqProtocol.ClientToServerTrafficInfo, 32, []),
                    HkdfInfoExample(PqProtocol.TrafficKeyInfo, 32, []),
                },
            },

            // 2. Transcript hash: SHA-256 over each fragment prefixed by its uint32_BE length.
            ["transcriptHash"] = new JsonObject
            {
                ["construction"] = "SHA-256( for each fragment: uint32_BE(len) || fragment )",
                ["examples"] = new JsonArray
                {
                    TranscriptExample("single fragment", [ClientRandom]),
                    TranscriptExample("two fragments", [ClientRandom, ServerRandom]),
                    TranscriptExample("empty then nonempty (order/empties are significant)", [[], ClientRandom]),
                },
            },

            // 3. Key schedule: salt = clientRandom || serverRandom || resumptionPsk; PRK = Extract(salt, sharedSecret);
            //    master = Expand(PRK, "master", ctx=transcriptHash); every secret expands from master.
            ["keySchedule"] = new JsonObject
            {
                ["saltConstruction"] = "clientRandom || serverRandom || resumptionPsk",
                ["labels"] = new JsonObject
                {
                    ["master"] = PqProtocol.MasterInfo,
                    ["clientToServerTraffic"] = PqProtocol.ClientToServerTrafficInfo,
                    ["serverToClientTraffic"] = PqProtocol.ServerToClientTrafficInfo,
                    ["clientFinished"] = PqProtocol.ClientFinishedInfo,
                    ["serverFinished"] = PqProtocol.ServerFinishedInfo,
                    ["resumption"] = PqProtocol.ResumptionInfo,
                },
                ["withoutResumption"] = ScheduleObject([], scheduleNoPsk),
                ["withResumption"] = ScheduleObject(ResumptionPsk, schedulePsk),
            },

            // 4. Record-layer keying, derived from a direction's traffic secret.
            ["recordKeying"] = new JsonObject
            {
                ["labels"] = new JsonObject
                {
                    ["key"] = PqProtocol.TrafficKeyInfo,
                    ["iv"] = PqProtocol.TrafficIvInfo,
                    ["keyUpdate"] = PqProtocol.KeyUpdateInfo,
                },
                ["nonceConstruction"] = "ivPrefix(4 bytes) || uint64_BE(sequence)",
                ["keyUpdateRatchet"] = "nextTrafficSecret = HKDF-Expand(trafficSecret, \"" + PqProtocol.KeyUpdateInfo + "\", 32)",
                ["input"] = new JsonObject { ["trafficSecret"] = Hex(c2s) },
                ["output"] = new JsonObject
                {
                    ["aesKey"] = Hex(trafficKey),
                    ["ivPrefix"] = Hex(ivPrefix),
                    ["nonceForSequence5"] = Hex(nonceForSeq5),
                    ["ratchetedTrafficSecret"] = Hex(ratcheted),
                },
            },
        };

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            // Human-facing artifact: keep apostrophes/quotes readable rather than \u-escaped.
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return root.ToJsonString(options) + "\n";
    }

    private static JsonObject HkdfInfoExample(string label, int length, byte[] context) => new()
    {
        ["input"] = new JsonObject
        {
            ["label"] = label,
            ["length"] = length,
            ["context"] = Hex(context),
        },
        ["output"] = new JsonObject { ["info"] = Hex(Hkdf.BuildInfo(label, length, context)) },
    };

    private static JsonObject TranscriptExample(string note, byte[][] fragments) => new()
    {
        ["note"] = note,
        ["input"] = new JsonObject
        {
            ["fragments"] = new JsonArray(fragments.Select(f => (JsonNode)Hex(f)).ToArray()),
        },
        ["output"] = new JsonObject { ["hash"] = Hex(Transcript.Hash(fragments)) },
    };

    private static JsonObject ScheduleObject(byte[] psk, KeySchedule s) => new()
    {
        ["input"] = new JsonObject
        {
            ["sharedSecret"] = Hex(SharedSecret),
            ["clientRandom"] = Hex(ClientRandom),
            ["serverRandom"] = Hex(ServerRandom),
            ["transcriptHash"] = Hex(TranscriptHash),
            ["resumptionPsk"] = Hex(psk),
        },
        ["output"] = new JsonObject
        {
            ["clientToServerTrafficSecret"] = Hex(s.ClientToServerTrafficSecret),
            ["serverToClientTrafficSecret"] = Hex(s.ServerToClientTrafficSecret),
            ["clientFinishedKey"] = Hex(s.ClientFinishedKey),
            ["serverFinishedKey"] = Hex(s.ServerFinishedKey),
            ["resumptionSecret"] = Hex(s.ResumptionSecret),
        },
    };

    private static byte[] NonceFor(byte[] ivPrefix, ulong sequence)
    {
        var nonce = new byte[12];
        ivPrefix.AsSpan(0, 4).CopyTo(nonce);
        for (int i = 0; i < 8; i++)
        {
            nonce[11 - i] = (byte)(sequence >> (8 * i));
        }

        return nonce;
    }

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    private static byte[] Pattern(byte seed, int length)
    {
        var bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = (byte)(seed ^ (byte)i);
        }

        return bytes;
    }

    private static string RepoRoot([CallerFilePath] string path = "")
    {
        // tests/PostQuantum.SecureChannel.Tests/InteropVectorTests.cs → repo root is three levels up.
        var dir = Path.GetDirectoryName(path)!;
        return Path.GetFullPath(Path.Combine(dir, "..", ".."));
    }
}
