// PostQuantum.SecureChannel — device / edge-agent enrollment demo.
//
// A realistic first-run enrollment lifecycle for a fleet device or edge agent talking to a control
// plane over a post-quantum secure channel, all on TCP loopback:
//
//   Phase 1 — Enrollment.  The device boots for the first time, generates its own long-term ML-DSA
//             identity, and connects to the control plane's *enrollment* endpoint. That endpoint
//             requires client authentication (the device proves it holds its private key) but does not
//             yet restrict *which* device — it records the device's fingerprint as "pending approval".
//   Phase 2 — Approval.  An operator compares the fingerprint out of band and approves it. The control
//             plane adds the device's public key to its authorized-clients allowlist.
//   Phase 3 — Operational.  The device reconnects to the *operational* endpoint, which admits only
//             approved devices. The control plane now knows exactly which device connected.
//   Phase 4 — Rotation.  The device rolls to a fresh identity. Both old and new keys are trusted during
//             an overlap window (re-enroll + approve the new one), then the old key is retired.
//
//   dotnet run --project samples/DeviceEnrollment
//
// The control plane's own identity is pinned on the device out of band (shipped in firmware / config).
// This is raw-key pinning with an explicit approval step — no PKI, no CA. See docs/operations.md.
//
// To God be the glory. — 1 Corinthians 10:31

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.SecureChannel;
using PostQuantum.SecureChannel.Transport;

// ── The control plane has a long-term identity, pinned on the device out of band. ──────────────────
using var controlPlaneIdentity = PqIdentity.Create();
var pinnedControlPlaneKey = controlPlaneIdentity.PublicKey.ToBase64();
Console.WriteLine($"Control plane identity:  {controlPlaneIdentity.PublicKey.ShortFingerprint()}");
Console.WriteLine("(the device has this pinned in firmware)\n");

// The control plane's fleet registry: fingerprint -> approved device public key.
var approvedDevices = new Dictionary<string, PqIdentityPublicKey>();

// ── Phase 1: the device boots, creates its identity, and enrolls. ──────────────────────────────────
Console.WriteLine("── Phase 1: first-boot enrollment ──────────────────────────────────────────────");
var device = PqIdentity.Create();

// A real device persists its seed to secure storage (TPM, keystore, encrypted file). We simulate that
// by exporting the seed; the identity survives reboots by re-importing it.
byte[] deviceSeed = device.ExportPrivateSeed();
Console.WriteLine($"[device] generated identity {device.PublicKey.ShortFingerprint()} and persisted its seed");

var pendingFingerprint = await EnrollAsync(device, pinnedControlPlaneKey);

// ── Phase 2: an operator approves the fingerprint out of band. ─────────────────────────────────────
Console.WriteLine("\n── Phase 2: operator approval ──────────────────────────────────────────────────");
Console.WriteLine($"[operator] verifying fingerprint {pendingFingerprint.Device.ShortFingerprint()} out of band… approved");
approvedDevices[pendingFingerprint.Device.Fingerprint()] = pendingFingerprint.Device;

// ── Phase 3: the device reconnects to the operational endpoint and is recognized. ──────────────────
Console.WriteLine("\n── Phase 3: operational connection ─────────────────────────────────────────────");
device.Dispose();
using var rebootedDevice = PqIdentity.ImportPrivateSeed(deviceSeed); // survives a reboot
await OperateAsync(rebootedDevice, pinnedControlPlaneKey, approvedDevices, "telemetry: temp=21.4C ok");

// ── Phase 4: identity rotation with an overlap window. ─────────────────────────────────────────────
Console.WriteLine("\n── Phase 4: identity rotation ──────────────────────────────────────────────────");
using var rotatedDevice = PqIdentity.Create();
Console.WriteLine($"[device] rotating to new identity {rotatedDevice.PublicKey.ShortFingerprint()}");
var rotatedPending = await EnrollAsync(rotatedDevice, pinnedControlPlaneKey);
Console.WriteLine($"[operator] approving rotated fingerprint {rotatedPending.Device.ShortFingerprint()}");
approvedDevices[rotatedPending.Device.Fingerprint()] = rotatedPending.Device; // both keys trusted now
await OperateAsync(rotatedDevice, pinnedControlPlaneKey, approvedDevices, "telemetry: post-rotation heartbeat");

// Retire the old key once every device has rolled.
approvedDevices.Remove(rebootedDevice.PublicKey.Fingerprint());
Console.WriteLine($"[control plane] retired old key {rebootedDevice.PublicKey.ShortFingerprint()}; {approvedDevices.Count} device key(s) trusted");

CryptographicOperations.ZeroMemory(deviceSeed);
rebootedDevice.Dispose();
Console.WriteLine("\nDone. To God be the glory.");

// ────────────────────────────────────────────────────────────────────────────────────────────────
// Enrollment: the control plane authenticates the device (proves key possession) but accepts any
// device, capturing its fingerprint for operator approval. Returns the pinned device identity.
async Task<(PqIdentityPublicKey Device, string Note)> EnrollAsync(PqIdentity deviceIdentity, string pinnedCp)
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;

    var serverTask = Task.Run(async () =>
    {
        using var tcp = await listener.AcceptTcpClientAsync();
        await using var channel = await PqSecureChannel.AcceptAsync(
            tcp.GetStream(),
            new PqServerOptions
            {
                Identity = controlPlaneIdentity,
                RequireClientAuthentication = true, // device MUST prove it holds its key…
                // …but no AuthorizedClients allowlist here: enrollment accepts any authenticated device.
            },
            handshakeTimeout: TimeSpan.FromSeconds(10));

        var deviceKey = channel.Session.RemoteIdentity!;
        Console.WriteLine($"[control plane] enrollment request from {deviceKey.ShortFingerprint()} — recording as pending");
        return deviceKey;
    });

    using (var tcp = new TcpClient())
    {
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await using var channel = await PqSecureChannel.ConnectAsync(
            tcp.GetStream(),
            new PqClientOptions
            {
                ServerIdentity = PqIdentityPublicKey.FromBase64(pinnedCp),
                ClientIdentity = deviceIdentity, // the device presents its identity
            },
            handshakeTimeout: TimeSpan.FromSeconds(10));
        Console.WriteLine($"[device] enrolled over PQ channel; verified control plane {channel.Session.RemoteIdentity!.ShortFingerprint()}");
    }

    var pinned = await serverTask;
    listener.Stop();
    return (pinned, "pending");
}

// Operational: the control plane admits only approved devices (allowlist), then exchanges data.
async Task OperateAsync(
    PqIdentity deviceIdentity, string pinnedCp, IReadOnlyDictionary<string, PqIdentityPublicKey> approved, string payload)
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;

    var serverTask = Task.Run(async () =>
    {
        using var tcp = await listener.AcceptTcpClientAsync();
        await using var channel = await PqSecureChannel.AcceptAsync(
            tcp.GetStream(),
            new PqServerOptions
            {
                Identity = controlPlaneIdentity,
                // A non-empty allowlist admits only approved devices (and implies client auth).
                AuthorizedClients = approved.Values.ToArray(),
            },
            handshakeTimeout: TimeSpan.FromSeconds(10));

        Console.WriteLine($"[control plane] accepted approved device {channel.Session.RemoteIdentity!.ShortFingerprint()}");
        var buf = new byte[256];
        int n = await channel.ReadAsync(buf);
        Console.WriteLine($"[control plane] received: {Encoding.UTF8.GetString(buf, 0, n)}");
    });

    using (var tcp = new TcpClient())
    {
        await tcp.ConnectAsync(IPAddress.Loopback, port);
        await using var channel = await PqSecureChannel.ConnectAsync(
            tcp.GetStream(),
            new PqClientOptions
            {
                ServerIdentity = PqIdentityPublicKey.FromBase64(pinnedCp),
                ClientIdentity = deviceIdentity,
            },
            handshakeTimeout: TimeSpan.FromSeconds(10));
        await channel.WriteAsync(Encoding.UTF8.GetBytes(payload));
        Console.WriteLine($"[device] sent operational payload");
    }

    await serverTask;
    listener.Stop();
}
