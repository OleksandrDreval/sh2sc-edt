# SH2SC-EDT Documentation {#mainpage}

## Project Identity

**SH2SC-EDT** — *Self-Healing Hardware and Software Complex for Encrypted Data Transmission*.

**C2P-ARQ** — *ChaCha-Poly Automatic Repeat reQuest*. The custom session-layer protocol that
governs all communication between Node A (Transmitter) and Node B (Receiver).

---

## System Overview

SH2SC-EDT is a fault-tolerant, cryptographically secured communication complex implemented on
two Arduino Nano microcontrollers (ATmega328P, 8-bit AVR, 16 MHz, 2 KB SRAM). The system
demonstrates that authenticated encrypted data transmission is achievable over a
hardware-attacked, noise-injected channel using only a 256-bit pre-shared symmetric key and
a resource-constrained 8-bit MCU.

The simulation environment is **SimulIDE** (real-time circuit simulator). All firmware is
strictly non-blocking: no `delay()` calls in any loop body, all timing via `millis()` deltas.

Academic context: university coursework for the discipline *Computer Systems Architecture*.

---

## Protocol — C2P-ARQ

The C2P-ARQ protocol implements three phases per transmission session:

**Phase 1 — Session Open (SYN Handshake)**

> TX generates a 12-byte CSPRNG nonce and sends it inside a `HelloPacket` (FLAG\_SYN).
> RX stores the nonce, installs `MASTER_PSK`, and sends `ACK_BYTE`.

**Phase 2 — Data Transfer (Stop-and-Wait ARQ)**

> For each note: TX derives a per-packet IV, encrypts the 4-byte payload with ChaCha20,
> appends a truncated 8-byte Poly1305 MAC, and sends the frame preceded by the `0xAA 0x55`
> sync preamble. RX verifies the MAC before acting on the payload.
> On `ACK`: advance index. On `NACK` or timeout: retransmit (up to `MAX_RETRIES = 50`).

**Phase 3 — Session Close (FIN Teardown)**

> TX sends a `FLAG_FIN` frame (authenticated, zero payload). Both nodes erase
> `s_sessionNonce` from RAM via `memset()` upon authenticated teardown.

### Per-Packet Nonce Derivation

No IV is transmitted on the wire. Each packet's IV is derived locally:

```
packetNonce[0..11] = s_sessionNonce[0..11]   // local copy — original never mutated
packetNonce[10]   ^= (seqNum >> 8) & 0xFF
packetNonce[11]   ^= (seqNum)      & 0xFF
```

All 65,536 possible `seqNum` values produce distinct IVs without any additional transmission.

### Frame Format

| Frame | Wire size | Structure |
|-------|----------|-----------|
| `HelloPacket` | 15 bytes | `0xAA 0x55` + `flags(1)` + `nonce(12)` |
| `DataPacket` | 17 bytes | `0xAA 0x55` + `flags(1)` + `seq_num(2)` + `ciphertext(4)` + `mac(8)` |

The 3-byte AAD `{flags, seq_lo, seq_hi}` is authenticated but not encrypted; any bit-flip
in the flags byte or sequence number fails the MAC.

---

## Architecture — Fat Server / Thin Client

The system is designed around a deliberate asymmetric split:

| Property | Node A — Transmitter ("The Conductor") | Node B — Receiver ("The Synthesizer") |
|----------|----------------------------------------|---------------------------------------|
| **State** | Owns `melodyIndex`, session lifecycle, retry counters | Stateless between packets; only holds `s_sessionNonce` |
| **Data** | Full melody in `PROGMEM` (530 notes) | Universal 21-entry frequency dictionary |
| **FSM** | 9 states: `IDLE` through `WAITING_FIN_ACK` + `RECONNECTING` | Byte-parser: `WAIT_AA → WAIT_55 → READ_TYPE → READ_PAYLOAD` |
| **Crypto** | Encrypts, generates nonce, sends MAC | Decrypts, verifies MAC, rejects on mismatch |

This split serves two purposes: memory efficiency (expensive state lives on TX) and
extensibility (replacing note indices with generic command IDs requires zero RX changes).

---

## Self-Healing — Auto-Resume

The defining property of SH2SC-EDT is automatic session recovery without data loss and
without operator intervention.

**Survival sequence after sustained link disruption:**

1. TX retransmits the current packet up to `MAX_RETRIES = 50` times
   (`ACK_TIMEOUT_MS = 50 ms` per attempt — `2.5 s` total window).
2. `suspendSession()` fires: `s_sessionNonce` is zeroed, `retryCount` is reset.
   **`melodyIndex` is deliberately preserved** — this is the self-healing checkpoint.
3. TX enters `TxState::RECONNECTING` and broadcasts a fresh `HelloPacket` every
   `RECONNECT_INTERVAL_MS = 2000 ms`.
4. When the channel recovers, RX receives `HelloPacket`, stores the new nonce, sends `ACK`.
5. TX reads the preserved `melodyIndex` and **resumes from the exact note of failure** —
   not from the beginning.

Without Self-Healing a noise burst exceeding `2.5 s` permanently halts transmission.
With it, the complex is fully autonomous.

---

## Dynamic Smart Watchdog (Receiver)

The receiver cannot detect a TX power cut without a FLAG\_FIN packet. A static timeout
would fire too early on long notes or too late on short ones.

**Solution:** after each authenticated `DataPacket`, RX updates:

```
current_timeout_limit = durationMs + NETWORK_GRACE_PERIOD_MS  // 3000 ms
last_valid_packet_time = millis()
```

`NETWORK_GRACE_PERIOD_MS = 3000 ms` absorbs the worst-case TX retry storm
(`50 × 50 ms = 2500 ms`). On timeout: `s_sessionNonce` is zeroed, the session is released,
and the parser resets to `WAIT_AA` — ready for a new handshake without an MCU restart.

---

## Cryptographic Security Properties

- `MASTER_PSK[32]` (256-bit) compiled into firmware; never transmitted, never logged.
- Per-session 96-bit CSPRNG nonce; seeded from 256 bits of hardware entropy
  (ring oscillator, uninitialised SRAM, temperature ADC, TCNT1, A0 noise, `random()`).
- Truncated 8-byte Poly1305 MAC on every frame (full tag computed, first 8 bytes sent).
- Session nonce erased with `memset(s_sessionNonce, 0, 12)` on every close or failure.
- Bounds check on `noteIndex < NOTE_DICT_SIZE` before any array access — prevents
  out-of-bounds reads on ATmega328P from MAC-bypassed corrupted payloads.
- No `String`, `new`, or `malloc()` — all buffers statically allocated at compile time.

---

## Source Layout

| Path | Contents |
|------|----------|
| `TransmitterNode/TransmitterNode.ino` | TX FSM implementation, entropy pool, packet construction |
| `TransmitterNode/transmitter.h` | TX public API, `TxState` enum, pin/timing constants |
| `TransmitterNode/protocol.h` | Shared packed structs, flag constants, `MASTER_PSK` |
| `TransmitterNode/csprng.h` | ChaCha20-based CSPRNG (TX variant) |
| `TransmitterNode/melody.h` | PROGMEM melody table (Imperial March, 530 notes) |
| `ReceiverNode/ReceiverNode.ino` | RX byte-parser FSM, crypto pipeline, note playback |
| `ReceiverNode/receiver.h` | RX public API, `RxState` enum, pin constants |
| `ReceiverNode/protocol.h` | Shared packed structs (RX copy) |
| `ReceiverNode/csprng.h` | ChaCha20-based CSPRNG (RX variant, no button jitter) |
| `docs/en/` | English Doxygen documentation source |
| `docs/uk/` | Ukrainian Doxygen documentation source |
