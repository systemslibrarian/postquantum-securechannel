// QueueEnvelope — message-envelope encryption for an untrusted broker.
//
// Two services have a shared PQ secure session (established via a real handshake at startup,
// simulated here with PqHandshakeHarness). They then exchange application messages through an
// in-memory "queue" that stands in for SQS / Service Bus / Kafka / RabbitMQ. The broker only ever
// sees AEAD-protected envelopes; if it were compromised it could not read or forge messages.
//
//   dotnet run --project samples/QueueEnvelope
//
// To God be the glory. — 1 Corinthians 10:31

using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.Testing;

// One-time session establishment between producer and consumer. In production, replace with a real
// transport-driven handshake (TCP/WebSocket/etc.) and cache the resulting session per peer.
using var harness = PqHandshakeHarness.Create(mutual: true);
var producer = harness.Client;
var consumer = harness.Server;

// The "broker": a queue that knows nothing about the contents of messages it ferries.
var broker = new ConcurrentQueue<byte[]>();

// Producer side: serialize a domain message, attach routing AAD, encrypt, enqueue.
for (int i = 0; i < 3; i++)
{
    var order = new { OrderId = $"ord-{i:0000}", Customer = "alice", AmountCents = 1234 + i };
    var payload = JsonSerializer.SerializeToUtf8Bytes(order);
    var aad = Encoding.UTF8.GetBytes($"queue=orders;tenant=acme;v=1");

    var envelope = producer.Encrypt(payload, aad);
    broker.Enqueue(envelope);

    Console.WriteLine($"[producer] enqueued order {order.OrderId} ({envelope.Length} bytes ciphertext)");
}

// Consumer side: dequeue, validate AAD (envelope routing/version), decrypt, deserialize.
while (broker.TryDequeue(out var envelope))
{
    var aad = Encoding.UTF8.GetBytes("queue=orders;tenant=acme;v=1");
    var plaintext = consumer.Decrypt(envelope, aad);
    using var doc = JsonDocument.Parse(plaintext);
    Console.WriteLine($"[consumer] received order {doc.RootElement.GetProperty("OrderId").GetString()}");
}

Console.WriteLine();
Console.WriteLine("The broker (in-memory queue here, RabbitMQ/SQS/etc. in production) never saw plaintext.");
Console.WriteLine($"Producer identity: {harness.ClientIdentity!.PublicKey.ShortFingerprint()}");
Console.WriteLine($"Consumer identity: {harness.ServerIdentity.PublicKey.ShortFingerprint()}");
