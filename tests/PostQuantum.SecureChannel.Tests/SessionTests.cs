using System.Text;
using Xunit;

namespace PostQuantum.SecureChannel.Tests;

public class SessionTests
{
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
    public void Sequence_IncrementsPerRecord()
    {
        var (client, server) = Establish();

        Assert.Equal(0UL, client.RecordsSent);
        client.Encrypt(Encoding.UTF8.GetBytes("one"));
        client.Encrypt(Encoding.UTF8.GetBytes("two"));
        Assert.Equal(2UL, client.RecordsSent);
        Assert.Equal(0UL, server.RecordsReceived);
    }

    [Fact]
    public void OrderedRecords_DecryptInOrder()
    {
        var (client, server) = Establish();

        var r1 = client.Encrypt(Encoding.UTF8.GetBytes("first"));
        var r2 = client.Encrypt(Encoding.UTF8.GetBytes("second"));

        Assert.Equal("first", Encoding.UTF8.GetString(server.Decrypt(r1)));
        Assert.Equal("second", Encoding.UTF8.GetString(server.Decrypt(r2)));
    }

    [Fact]
    public void OutOfOrderRecord_IsRejected()
    {
        var (client, server) = Establish();

        var r1 = client.Encrypt(Encoding.UTF8.GetBytes("first"));
        var r2 = client.Encrypt(Encoding.UTF8.GetBytes("second"));

        // Deliver the second record first.
        Assert.Throws<PqDecryptionException>(() => server.Decrypt(r2));
        // The expected record still works.
        Assert.Equal("first", Encoding.UTF8.GetString(server.Decrypt(r1)));
    }

    [Fact]
    public void ReplayedRecord_IsRejected()
    {
        var (client, server) = Establish();

        var record = client.Encrypt(Encoding.UTF8.GetBytes("once"));
        _ = server.Decrypt(record);

        Assert.Throws<PqDecryptionException>(() => server.Decrypt(record));
    }

    [Fact]
    public void TamperedRecord_IsRejected()
    {
        var (client, server) = Establish();

        var record = client.Encrypt(Encoding.UTF8.GetBytes("integrity"));
        record[^1] ^= 0x01; // corrupt the tag

        Assert.Throws<PqDecryptionException>(() => server.Decrypt(record));
    }

    [Fact]
    public void AssociatedData_MustMatch()
    {
        var (client, server) = Establish();

        var aad = Encoding.UTF8.GetBytes("context-A");
        var record = client.Encrypt(Encoding.UTF8.GetBytes("payload"), aad);

        Assert.Throws<PqDecryptionException>(() => server.Decrypt(record, Encoding.UTF8.GetBytes("context-B")));
        Assert.Equal("payload", Encoding.UTF8.GetString(server.Decrypt(record, aad)));
    }

    [Fact]
    public void EmptyPlaintext_RoundTrips()
    {
        var (client, server) = Establish();

        var record = client.Encrypt(ReadOnlySpan<byte>.Empty);
        Assert.Empty(server.Decrypt(record));
    }

    [Fact]
    public void IndependentDirections_DoNotInterfere()
    {
        var (client, server) = Establish();

        // Both sides send their first record concurrently (same sequence number, different keys).
        var fromClient = client.Encrypt(Encoding.UTF8.GetBytes("c2s"));
        var fromServer = server.Encrypt(Encoding.UTF8.GetBytes("s2c"));

        Assert.Equal("c2s", Encoding.UTF8.GetString(server.Decrypt(fromClient)));
        Assert.Equal("s2c", Encoding.UTF8.GetString(client.Decrypt(fromServer)));
    }
}
