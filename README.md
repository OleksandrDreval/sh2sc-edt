# SH2SC-EDT

**Self-Healing Hardware and Software Complex for Encrypted Data Transmission**

---

## Abstract

SH2SC-EDT is a fault-tolerant, cryptographically secured communication complex built on two
Arduino Nano (ATmega328P) microcontrollers. It implements a custom transport/session-layer
protocol — **C2P-ARQ (ChaCha20-Poly1305 Automatic Repeat reQuest)** — that provides authenticated
encryption (ChaCha20-Poly1305 AEAD), guaranteed packet delivery via Stop-and-Wait ARQ, and a
full three-phase session lifecycle (SYN / DAT / FIN).

The defining property of the complex is **Self-Healing**: upon link disruption, the transmitter
node preserves its position in the data stream and autonomously re-establishes the session from
the exact point of failure without operator intervention and without data loss. All logic on both
nodes is implemented as non-blocking Finite State Machines running at 100% real-time in
SimulIDE. Dynamic memory allocation is architecturally prohibited; the entire firmware operates
within the 2 KB SRAM budget of the ATmega328P.

---
