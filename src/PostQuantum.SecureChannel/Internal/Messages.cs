using PostQuantum.SecureChannel.Cryptography;

namespace PostQuantum.SecureChannel.Internal;

/// <summary>First handshake flight: offered protocol versions, the client's ephemeral X-Wing public key, and a nonce.</summary>
internal sealed class ClientHello
{
    internal required byte[] SupportedVersions { get; init; }
    internal required byte[] ClientRandom { get; init; }
    internal required byte[] KemPublicKey { get; init; }

    internal byte[] Serialize() => new WireWriter()
        .WriteByte(PqProtocol.Version)
        .WriteBlock(SupportedVersions)
        .WriteBlock(ClientRandom)
        .WriteBlock(KemPublicKey)
        .ToArray();

    internal static ClientHello Parse(ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new WireReader(data);
            RequireFormat(reader.ReadByte());
            var versions = reader.ReadBlock();
            var random = reader.ReadBlock();
            var kem = reader.ReadBlock();
            Expect(versions.Length is > 0 and <= 64, "supported versions list");
            Expect(random.Length == PqProtocol.RandomSize, "client random size");
            Expect(kem.Length == XWing.PublicKeySize, "KEM public key size");
            Expect(reader.IsEmpty, "trailing bytes after ClientHello");
            return new ClientHello { SupportedVersions = versions, ClientRandom = random, KemPublicKey = kem };
        }
        catch (FormatException ex)
        {
            throw new PqProtocolException("Malformed ClientHello.", ex);
        }
    }

    private static void RequireFormat(byte version)
    {
        if (version != PqProtocol.Version)
        {
            throw new PqProtocolException($"Unsupported message format {version}; expected {PqProtocol.Version}.");
        }
    }

    private static void Expect(bool condition, string what)
    {
        if (!condition)
        {
            throw new PqProtocolException($"Invalid {what} in handshake message.");
        }
    }
}

/// <summary>Second flight: the negotiated version, the server's ciphertext, optional identity, and signature.</summary>
internal sealed class ServerHello
{
    internal required byte NegotiatedVersion { get; init; }
    internal required byte[] ServerRandom { get; init; }
    internal required byte[] KemCiphertext { get; init; }
    internal required byte[] ServerIdentityPublicKey { get; init; }
    internal byte[] Signature { get; set; } = [];

    private WireWriter WriteBody() => new WireWriter()
        .WriteByte(PqProtocol.Version)
        .WriteByte(NegotiatedVersion)
        .WriteBlock(ServerRandom)
        .WriteBlock(KemCiphertext)
        .WriteBlock(ServerIdentityPublicKey);

    /// <summary>The signed portion of the message (everything except the signature itself).</summary>
    internal byte[] SerializeBody() => WriteBody().ToArray();

    internal byte[] Serialize() => WriteBody().WriteBlock(Signature).ToArray();

    internal static ServerHello Parse(ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new WireReader(data);
            if (reader.ReadByte() != PqProtocol.Version)
            {
                throw new PqProtocolException("Unsupported message format in ServerHello.");
            }

            var negotiated = reader.ReadByte();
            var random = reader.ReadBlock();
            var ciphertext = reader.ReadBlock();
            var identity = reader.ReadBlock();
            var signature = reader.ReadBlock();

            if (random.Length != PqProtocol.RandomSize)
            {
                throw new PqProtocolException("Invalid server random size in ServerHello.");
            }

            if (ciphertext.Length != XWing.CiphertextSize)
            {
                throw new PqProtocolException("Invalid KEM ciphertext size in ServerHello.");
            }

            if (!reader.IsEmpty)
            {
                // Reject non-canonical encodings: trailing bytes are covered neither by the server
                // signature nor by the client's transcript re-serialization, so an active attacker could
                // otherwise append data undetected. A conformant ServerHello ends exactly at the signature.
                throw new PqProtocolException("Trailing bytes after ServerHello.");
            }

            return new ServerHello
            {
                NegotiatedVersion = negotiated,
                ServerRandom = random,
                KemCiphertext = ciphertext,
                ServerIdentityPublicKey = identity,
                Signature = signature,
            };
        }
        catch (FormatException ex)
        {
            throw new PqProtocolException("Malformed ServerHello.", ex);
        }
    }
}

/// <summary>Third flight: client key-confirmation MAC plus optional client authentication.</summary>
internal sealed class ClientFinished
{
    internal required byte[] ClientIdentityPublicKey { get; init; }
    internal required byte[] ClientSignature { get; init; }
    internal required byte[] FinishedMac { get; init; }

    internal byte[] Serialize() => new WireWriter()
        .WriteByte(PqProtocol.Version)
        .WriteBlock(ClientIdentityPublicKey)
        .WriteBlock(ClientSignature)
        .WriteBlock(FinishedMac)
        .ToArray();

    internal static ClientFinished Parse(ReadOnlySpan<byte> data)
    {
        try
        {
            var reader = new WireReader(data);
            if (reader.ReadByte() != PqProtocol.Version)
            {
                throw new PqProtocolException("Unsupported message format in ClientFinished.");
            }

            var clientFinished = new ClientFinished
            {
                ClientIdentityPublicKey = reader.ReadBlock(),
                ClientSignature = reader.ReadBlock(),
                FinishedMac = reader.ReadBlock(),
            };
            if (!reader.IsEmpty)
            {
                throw new PqProtocolException("Trailing bytes after ClientFinished.");
            }

            return clientFinished;
        }
        catch (FormatException ex)
        {
            throw new PqProtocolException("Malformed ClientFinished.", ex);
        }
    }
}
