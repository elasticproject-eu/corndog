# CornDog - Fair Exchange Migration

A Rust + WebAssembly implementation for securely transferring data between two parties, with a Trusted Third Party (TTP) available only for dispute resolution.

---

## Table of Contents

1. [What this project does](#1-what-this-project-does)
2. [Protocol overview](#2-protocol-overview)
3. [Project structure](#3-project-structure)
4. [Prerequisites](#4-prerequisites)
5. [Building the project](#5-building-the-project)
6. [Key management](#6-key-management)
7. [Running the protocol](#7-running-the-protocol)
8. [Understanding the output](#8-understanding-the-output)
9. [Testing timeout and TTP scenarios](#9-testing-timeout-and-ttp-scenarios)

---

## 1. What this project does

Two parties — **Source (RS)** and **Destination (RD)** — want to exchange a piece of data such that either both parties end up with a cryptographic proof the exchange happened, or neither does. This is the *fairness* guarantee.

The protocol is **optimistic**: in the optimal case, the two parties complete the exchange directly between themselves without involving a third party at all. The TTP is only contacted when one party suspects the other is misbehaving or has gone offline.

At the end of a successful exchange both parties independently print the same JSON receipt to stdout:

```json
{
  "source_id": "<hex of source long-term public key>",
  "dest_id": "<hex of destination long-term public key>",
  "data": "SomeStringHere",
  "hash": "<BLAKE3 hex of SomeStringHere>",
  "signature_source": "<hex of BLAKE3(secret_as)>",
  "signature_destination": "<hex of BLAKE3(secret_ad)>",
  "status": "commit",
  "method": "direct"
}
```

- `status: "commit"` — the exchange completed successfully.
- `status: "rollback"` — the exchange was aborted.
- `method: "direct"` — completed without TTP intervention.
- `method: "arbitrated"` — the TTP was contacted to resolve or abort.

---

## 2. Protocol overview

### Parties

| Name | Short | Role |
|---|---|---|
| Agent Source | AS | Receives input from RS and takes care of the logical part of the fair exchange protocol |
| Agent Destination | AD | Receives input from RD and takes care of the logical part of the fair exchange protocol |
| Runtime Source | RS | Initiates the exchange, loads AS component, holds the data and interacts with AS |
| Runtime Destination | RD | Receives the data from RS, loads AD component, interacts with AD |
| Runtime TTP | TTP | Trusted third party; only contacted on timeout |

### Optimal / Normal Case

RS                                  RD                         TTP
|                                   |                           |
|-- StringTransfer (data) --------->|                           |
|                                   |                           |
|<== Fair Exchange Protocol =======>|                           |
|                                   |                           |
|-- CommunicationMessage(AS) ------>|                           |
|<-- CommunicationMessage(AD) ------|                           |
|-- secret_as (32 bytes) ---------->|                           |
|<-- secret_ad (32 bytes) ----------|                           |
|                                   |                           |
[Both print JSON receipt to stdout]

### What the messages contain

1. **CommunicationMessage(AS):** Source's ephemeral signing key, a contract (hash of data, both long-term public keys, `commitment_as = BLAKE3(secret_as)`), and Source's signature over it.
2. **CommunicationMessage(AD):** Same structure but for Destination — includes `commitment_ad = BLAKE3(secret_ad)` and Destination's signature.
3. **secret_as / secret_ad:** 32-byte random secrets. Once received and verified against the commitment, the holder has proof the other party committed.

### Timeout / TTP path

If either party does not receive a message within the timeout window (default 5 seconds):

- **Source** hasn't received AD's verification → sends **AbortRequest** to TTP.
- **Source or Destination** hasn't received the other's secret → sends **ResolveRequest** to TTP.

The TTP is stateful per session (keyed by Source's ephemeral verifying key). Once it decides Abort or Resolve for a session, it never changes its mind, ensuring consistency.

You must share the **public key** files with the other party before running. Source needs `dest.key.pub`; Destination needs `source.key.pub`.

---

## 7. Running the protocol

Open **three terminals** in the project root. Start them in this order.

### Terminal 1 — TTP (must start first)

```bash
./target/release/runtime_ttp
```

TTP listens on `127.0.0.1:9705`.

### Terminal 2 — Destination (start second)

```bash
echo "SomeStringHere" | ./target/release/runtime_destination \
    --dest-private-key dest.key \
    --source-public-key source.key.pub
```

Destination listens on `127.0.0.1:7760` and waits for Source.

### Terminal 3 — Source (start last)

```bash
echo "SomeStringHere" | ./target/release/runtime_source \
    --source-private-key source.key \
    --destination-public-key dest.key.pub
```

**Important:** The string you `echo` must be identical in both Terminal 2 and Terminal 3. The protocol verifies this via BLAKE3 hash comparison before proceeding.

### Expected output

Both Terminal 2 and Terminal 3 print to **stdout**:

```json
{
  "source_id": "f425f42fa0de1c5023a3b044faeb67c02616b8a0deee185e7422cabb441f924c",
  "dest_id": "fc1ee006b897eba08872ee5272e6a1831d1556c9f868263bb6445c4e618f4289",
  "data": "SomeStringHere",
  "hash": "4b38951afc2ca66b16842e904f2898103b72b396779c31286393884492c8ed15",
  "signature_source": "6a9d3209eb5f19125db22f0b29127349dbbe1b6a8f3d2d3eb941042e937433bf",
  "signature_destination": "0433a9e3761831bd2e2e7d5df89e4f532c9a12ac52570b740d018966e1ef547c",
  "status": "commit",
  "method": "direct"
}
```

Debug logs from both runtimes and the WASM agents go to **stderr** and do not appear on stdout. To silence them entirely: append `2>/dev/null` to your commands.

---

## 8. Understanding the output

| Field | Meaning |
|---|---|
| `source_id` | Source's long-term Ed25519 public key (hex). Identifies who initiated the exchange. |
| `dest_id` | Destination's long-term Ed25519 public key (hex). Identifies who received it. |
| `data` | The actual string that was exchanged. |
| `hash` | BLAKE3 hash of `data`. Both parties compute this independently — if they disagree, the protocol aborts. |
| `signature_source` | `BLAKE3(secret_as)` — Source's commitment. Proof that Source committed to this exchange. |
| `signature_destination` | `BLAKE3(secret_ad)` — Destination's commitment. Proof that Destination committed to this exchange. |
| `status` | `"commit"` — exchange succeeded. `"rollback"` — exchange was aborted. |
| `method` | `"direct"` — no TTP involvement. `"arbitrated"` — TTP was contacted to resolve or abort. |

Both parties produce **identical JSON** on success. You can verify fairness by checking that both receipts match and that `BLAKE3(data) == hash`.

---

## 9. Testing timeout and TTP scenarios

The runtimes contain commented-out sleep calls for simulating party misbehaviour. They are marked with `===== TEST CASE OF SLEEPING =====` comments.

**To simulate Source going offline after sending its contract (tests Destination's abort path):**

In `runtime_source/src/main.rs`, find the `counter == 2` block and uncomment:
```rust
tokio::time::sleep(DELAY_SECRET_AS).await;
```

**To simulate Destination going offline before sending its verification (tests Source's abort path):**

In `runtime_destination/src/main.rs`, find the `counter == 1` block and uncomment:
```rust
tokio::time::sleep(DELAY_MSG_AD).await;
```

When a timeout occurs, the affected party contacts the TTP. The TTP either:
- **ABORTs** — if contacted before any secret is revealed; the exchange is cancelled.
- **RESOLVEs** — if contacted after at least one secret was revealed; the TTP helps complete the exchange.

The TTP guarantees consistency: once a session is ABORTED it can never be RESOLVED, and vice versa.

---
