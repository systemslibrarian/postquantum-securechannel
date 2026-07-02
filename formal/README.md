# Formal model

A symbolic (Dolev-Yao) model of the PostQuantum.SecureChannel handshake, written for
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/).

> ## Status: authored, **not yet machine-checked**
>
> `xwing-handshake.pv` is a hand-written model. It has **not** been run through ProVerif in this
> repository's CI, and the maintainer has not yet completed a verified run. **Do not cite it as a
> proof of anything yet.** It is published as a precise, reviewable *specification* of the protocol's
> intended security argument and as the starting point for a verified run. Treating an unrun formal
> model as an assurance would be exactly the kind of false confidence this project tries to avoid
> (see [`../KNOWN-GAPS.md`](../KNOWN-GAPS.md) §10). Completing and CI-gating this is tracked in
> [`../ROADMAP.md`](../ROADMAP.md) (Tier 1, item 3).

## What it models

An **abstract** composition: the KEM (X-Wing), signatures (ML-DSA), hash, KDF, MAC, and AEAD are
treated as ideal primitives. The model reasons about how they are *wired together* — the three-message
flow, transcript binding (`th1`/`th2`), raw-key **pinning** of the server identity, and the `Finished`
key-confirmation MAC. That composition layer is precisely what primitive known-answer tests cannot
exercise.

Properties expressed:

- **Q1 — Session confidentiality.** A payload sent under the derived session key stays secret from a
  Dolev-Yao attacker (`query attacker(secretPayload)` should report *not derivable*).
- **Q2 — Server authentication / transcript agreement.** If the server accepts with transcript `th2`
  and key `k`, an honest client completed with the *same* `th2` and `k` — i.e. no attacker can make the
  two ends accept mismatched transcripts/keys.
- **Q3 — Client authentication** (mutual-auth variant) — sketched for the next iteration.

## What it does NOT model

- The internal structure of X-Wing / ML-KEM-768 / ML-DSA-65 (assumed to be a sound IND-CCA KEM and an
  EUF-CMA signature).
- The record layer: nonce/counter construction, epoch/rekey, and the anti-replay window. Those are
  covered by tests (`NonceUniquenessTests`, `PropertyTests`, `AntiReplay*Tests`), not here.
- Computational/complexity-theoretic soundness (this is a *symbolic* model), side channels, or the
  resumption PSK path (experimental).
- **Forward secrecy** as a distinct query — the ephemeral KEM key is modeled as session-local, but a
  post-session long-term-key-compromise phase has not been added yet.

## Running it (once ProVerif is installed)

```bash
# Install ProVerif (e.g. via OPAM: `opam install proverif`), then:
proverif formal/xwing-handshake.pv
```

Expected shape of a successful run: Q1 reports the secret is *not* derivable by the attacker, and Q2's
correspondence is *true*. Until that run is reproduced and wired into CI, the status banner above
stands. If you run it, please open an issue/PR with the output so the result can be recorded here and
the ROADMAP item advanced.

---

**To God be the glory.** — *1 Corinthians 10:31*
