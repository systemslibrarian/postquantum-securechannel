# Product notes: what would make 1 million developers want this?

The current technical foundation is strong, but mass adoption will not come from "post-quantum" by
itself. Most developers do not wake up wanting a new cryptography library. They want a safe, boring,
well-documented answer to a concrete problem:

- secure service-to-service traffic inside .NET systems
- protect long-lived secrets against harvest-now-decrypt-later risk
- replace ad-hoc application-layer encryption with something auditable
- add mutual authentication without designing a protocol themselves
- get transport-agnostic encrypted channels without becoming a cryptographer

If this project wants very large adoption, it needs to become the easiest credible answer to those
problems.

## 1. The product promise has to become sharper

The winning message is not "here is a post-quantum primitive bundle." It is:

- **"TLS-like security for app-level channels in pure .NET."**
- **"Three messages to establish a PQ-safe authenticated session."**
- **"Use your transport, keep your architecture, stop inventing crypto."**
- **"Pinned-identity secure channels for internal services, agents, workers, and devices."**

That framing is what makes the library legible to ordinary developers, staff engineers, and platform
teams.

## 2. Features that would materially increase demand

These are the features most likely to move the library from niche to widely desirable.

### A. First-class ASP.NET Core integration

This is the biggest missing adoption lever.

- `AddPostQuantumSecureChannel()` DI registration
- client/server middleware or endpoint filters
- `HttpClient` integration for app-layer request encryption
- Kestrel/TCP hosting examples
- background service and worker templates
- identity pinning from configuration, environment variables, Azure Key Vault, AWS Secrets Manager,
  Kubernetes secrets

If a developer can wire this into an ASP.NET Core service in 5 minutes, adoption changes.

### B. Developer ergonomics above raw message exchange

The core should stay transport-agnostic, but the package ecosystem should remove ceremony.

- opinionated handshake drivers for TCP, named pipes, QUIC, WebSockets, and gRPC streams
- source-generated config binding for pinned identities and session policies
- strongly named options profiles like `Recommended`, `HighThroughput`, `StrictReplay`, `MutualAuth`
- explicit key rotation helpers and identity rollover workflows
- clearer exception taxonomy with remediation guidance

The mental model should feel simpler than rolling custom TLS framing, not merely more correct.

### C. Operational features teams expect before rollout

- structured logs with redaction-safe event IDs
- metrics hooks for handshake success/failure, replay drops, rekeys, auth failures, version mismatch
- OpenTelemetry instrumentation
- deterministic health checks / self-tests for startup validation
- configurable handshake deadlines and payload limits at integration points
- documented rotation playbooks for identity keys and pinned keys

Security libraries get selected by platform teams when they are observable and governable.

### D. Migration-friendly identity story

Raw-key pinning is good, but teams will want a smoother trust distribution model.

- signed trust bundles
- multiple pinned keys for staged rotation
- trust store abstractions
- optional certificate-like packaging around ML-DSA identities without pretending to be PKI if it is not
- import/export helpers for PEM/JSON/config formats

The friction is rarely encryption. It is trust distribution.

### E. Strong interop and ecosystem credibility

- independent interoperability harnesses
- cross-language reference vectors and sample peers
- a small protocol spec that outsiders can implement against
- published compatibility matrix by version
- reproducible benchmark suite

Developers adopt security libraries faster when they believe the protocol is bigger than one repo.

## 3. The examples that would make people reach for it

The best examples are not toy echo apps. They are recognizable production shapes.

### Must-have examples

- **Microservice-to-microservice HTTP encryption**
  An ASP.NET Core API calling another API with pinned server identity, mutual auth, retries, and
  config-driven key loading.
- **Worker to control plane**
  A hosted service dialing a central coordinator over TCP/WebSockets with automatic rekeying.
- **Device or edge agent enrollment**
  First-run identity creation, fingerprint approval, rotation, and reconnect.
- **gRPC duplex stream protection**
  App-layer secure stream for environments where transport TLS termination is not enough.
- **Queue/message envelope encryption**
  Use the session layer to secure messages carried through an untrusted broker.
- **Database secret replication or backup metadata protection**
  Show the harvest-now-decrypt-later value in a concrete business workflow.

### "Steal this" examples

These should be short, polished, and copy-paste ready.

- secure chat over TCP
- remote admin channel
- CI runner talking to orchestrator
- plugin host talking to sandboxed plugin process
- service mesh alternative for a small .NET shop

If examples look like real work, developers can imagine themselves shipping with it.

## 4. Documentation that would actually convert users

The docs need to answer adoption questions in the order real engineers ask them.

### A. Start page: "Should I use this?"

One page should answer:

- what problem this solves
- what it does not solve
- when to use this instead of TLS
- when *not* to use it
- threat model in plain English
- current maturity and audit status

This avoids two bad outcomes: overselling to the reckless and losing serious engineers to ambiguity.

### B. Five-minute quick starts by scenario

- server-authenticated TCP
- mutual-auth service-to-service
- stream wrapper over existing transport
- rotation of pinned identity
- unordered transport with replay window

Each quick start should include:

- install command
- full runnable code
- expected output
- failure mode to test
- link to the deeper conceptual page

### C. A decision guide

Title it something blunt like:

- **"PostQuantum.SecureChannel vs TLS vs Noise vs libsodium"**

Include an honest comparison table covering:

- transport dependency
- mutual auth story
- operational maturity
- interop expectations
- browser compatibility
- post-quantum status
- when each choice is better

This page would likely drive adoption because it reduces selection risk.

### D. An operations guide

- how to pin identities
- how to rotate identities safely
- how to monitor failures
- how to choose replay policy
- how often to rekey
- payload/frame sizing guidance
- incident response steps if a key is compromised

Security libraries fail in the field when docs stop at the happy path.

### E. An architecture guide

- handshake flow diagram
- trust model
- transcript and key schedule overview
- what gets authenticated and when
- wire-format stability policy
- version negotiation behavior

This turns skeptical senior engineers into internal advocates.

### F. Copy-paste troubleshooting pages

- handshake failed: wrong pinned key
- replay rejection on unordered transport
- version mismatch during rollout
- key update confusion across long-lived streams
- framing errors and max frame size

Every error message should have a doc page or README section someone can search directly.

## 5. Proof points needed for wide trust

Mass adoption of a cryptographic library is mostly trust acquisition.

- independent security audit
- published threat model
- stable roadmap to `1.0`
- benchmark numbers against realistic payload sizes
- compatibility guarantees once `1.0` lands
- signed releases, SBOM, provenance
- public issue labels for security hardening, roadmap, and interoperability
- documented support policy

Without these, interest may be high, but rollout will stall in review boards.

## 6. Packaging and repo shape that help adoption

One package can remain the secure core, but adoption usually improves with a small ecosystem.

- `PostQuantum.SecureChannel` - core
- `PostQuantum.SecureChannel.Transport` - adapters and framing
- `PostQuantum.SecureChannel.AspNetCore` - DI, middleware, config, telemetry
- `PostQuantum.SecureChannel.Testing` - test helpers and deterministic fixtures

Also useful:

- samples organized by scenario, not only transport
- docs site with stable URLs
- versioned examples matching package versions
- a crisp README top section with one heroic production-shaped example

## 7. Language to use in marketing and docs

What will attract serious developers:

- **"transport-agnostic authenticated channel"**
- **"post-quantum confidentiality for long-lived secrets"**
- **"mutual authentication with pinned identities"**
- **"small .NET API, explicit trust model, no insecure knobs"**
- **"validated against published vectors, honest about current gaps"**

What will reduce credibility:

- hype about "quantum-proof"
- vague claims about replacing TLS everywhere
- claims of production readiness before audit and stabilization

## 8. Practical adoption roadmap

If the goal is not just a good library but a library many teams actually adopt, I would prioritize in
this order:

1. Make the README and docs scenario-first, not primitive-first.
2. Ship one excellent ASP.NET Core integration package.
3. Add OpenTelemetry, logs, and operational guidance.
4. Publish 3-5 production-shaped examples.
5. Write the honest comparison page versus TLS / Noise / libsodium.
6. Stabilize the API and wire-format expectations toward `1.0`.
7. Commission an independent audit.
8. Build interop credibility and release engineering trust signals.

## 9. Bottom line

One million developers will not want this because it uses ML-KEM, ML-DSA, or X-Wing. They will want
it if it becomes the clearest, safest, best-documented way to add authenticated, post-quantum-capable
application-layer channels to ordinary .NET systems.

The winning formula is:

- strong security defaults
- excellent framework integration
- production-shaped examples
- candid documentation
- operational maturity
- externally verifiable trust signals