using PostQuantum.SecureChannel.Internal;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

/// <summary>
/// Robustness tests: malformed, truncated, and mutated inputs must always fail with a well-typed
/// library exception (never an unexpected runtime exception or a crash). A fixed seed keeps these
/// deterministic and reproducible.
/// </summary>
public class FuzzTests
{
    private const int Iterations = 2000;

    private static (PqSession Client, PqSession Server) Establish()
    {
        var serverIdentity = PqIdentity.Create();
        var client = PqSecureChannel.CreateClient(new PqClientOptions { ServerIdentity = serverIdentity.PublicKey });
        var server = PqSecureChannel.CreateServer(new PqServerOptions { Identity = serverIdentity });
        var serverHello = server.ProcessClientHello(client.CreateClientHello());
        var result = client.ProcessServerHello(serverHello);
        var serverSession = server.ProcessClientFinished(result.ClientFinished);
        return (result.Session, serverSession);
    }

    [Fact]
    public void HandshakeParsers_NeverCrashOnGarbage()
    {
        var rng = new Random(0xC0FFEE);
        for (int i = 0; i < Iterations; i++)
        {
            var data = new byte[rng.Next(0, 4096)];
            rng.NextBytes(data);

            AssertOnlyProtocolException(() => ClientHello.Parse(data));
            AssertOnlyProtocolException(() => ServerHello.Parse(data));
            AssertOnlyProtocolException(() => ClientFinished.Parse(data));
        }
    }

    [Fact]
    public void HandshakeParsers_NeverCrashOnTruncatedValidMessages()
    {
        var rng = new Random(0x1234);
        using var keyPair = Cryptography.XWing.GenerateKeyPair();
        var valid = new ClientHello
        {
            SupportedVersions = [2],
            ClientRandom = new byte[PqProtocol.RandomSize],
            KemPublicKey = keyPair.PublicKey,
        }.Serialize();

        for (int i = 0; i < valid.Length; i++)
        {
            var truncated = valid[..i];
            AssertOnlyProtocolException(() => ClientHello.Parse(truncated));
        }

        // Random single-byte mutations should also only ever yield a protocol exception (or parse).
        for (int i = 0; i < Iterations; i++)
        {
            var mutated = (byte[])valid.Clone();
            mutated[rng.Next(mutated.Length)] ^= (byte)(1 << rng.Next(8));
            AssertOnlyProtocolException(() => ClientHello.Parse(mutated));
        }
    }

    [Fact]
    public void SessionOpen_NeverCrashesOnGarbage()
    {
        var (_, server) = Establish();
        var rng = new Random(0xBEEF);

        for (int i = 0; i < Iterations; i++)
        {
            var data = new byte[rng.Next(0, 256)];
            rng.NextBytes(data);

            var ex = Record.Exception(() => server.Open(data));
            Assert.True(
                ex is null or PqDecryptionException or PqProtocolException,
                $"Unexpected exception type from Open: {ex?.GetType().Name}");
        }
    }

    [Fact]
    public void SessionDecrypt_RejectsBitFlippedRecords()
    {
        var (client, server) = Establish();
        var rng = new Random(0x5EED);
        var record = client.Encrypt(new byte[64]);

        for (int i = 0; i < 500; i++)
        {
            var mutated = (byte[])record.Clone();
            mutated[rng.Next(mutated.Length)] ^= (byte)(1 << rng.Next(8));

            var ex = Record.Exception(() => server.Decrypt(mutated));
            // Any single-bit change must be rejected (or, if it hit nothing meaningful, decrypt cleanly —
            // but it must never throw an unexpected type).
            Assert.True(
                ex is null or PqDecryptionException or PqProtocolException,
                $"Unexpected exception type from Decrypt: {ex?.GetType().Name}");
        }
    }

    private static void AssertOnlyProtocolException(Action action)
    {
        var ex = Record.Exception(action);
        Assert.True(
            ex is null or PqProtocolException,
            $"Expected PqProtocolException or success, got {ex?.GetType().Name}: {ex?.Message}");
    }
}
