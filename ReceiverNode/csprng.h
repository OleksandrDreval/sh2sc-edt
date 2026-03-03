#pragma once

// csprng.h — ChaCha20-based CSPRNG for ATmega328P
//
// Requires the Arduino Crypto library by Rhys Weatherley:
//   https://github.com/rweather/arduinolibs
//   Library Manager: "Crypto" by Rhys Weatherley
//
// Architecture:
//   This module wraps the ChaCha20 stream cipher as a cryptographically
//   secure pseudo-random number generator (CSPRNG) for the ATmega328P.
//   The cipher is seeded once with 256 bits of hardware entropy collected by
//   generateEntropyPool(), then used as an unlimited deterministic keystream.
//
//   C = P ⊕ KS   →   C = 0x00…0 ⊕ KS = KS
//   Encrypting an all-zeros plaintext yields the raw ChaCha20 keystream.
//
// Buffer design (AVR memory optimisation):
//   ChaCha20 generates output in 64-byte (512-bit) blocks. Calling the cipher
//   for every byte would be prohibitively expensive on an 8-bit MCU, so this
//   module maintains a 64-byte cache. getSecureRandom32() draws 4 bytes per
//   call; the block is refilled (~100 µs at 16 MHz) every 16 calls.
//
// SRAM budget (approximate):
//   s_chacha object ......... ~140 bytes  (ChaCha20 key schedule + state)
//   s_keystreamBuf .......... 64 bytes
//   s_keystreamUsed ......... 1 byte
//   ─────────────────────────────────────
//   Total static overhead ... ~205 bytes  (of 2 048 bytes available)
//
// Usage:
//   1. Call initCSPRNG(seed) ONCE in setup() after generateEntropyPool().
//   2. Call getSecureRandom32() anywhere in loop() for 32 random bits.

#include <Arduino.h>
#include <ChaCha.h>

// Configuration

// One ChaCha20 keystream block = 64 bytes = 512 bits.
// Must be a multiple of 4 so that getSecureRandom32() never spans two blocks.
static const uint8_t CSPRNG_BLOCK_BYTES = 64u;

// Module-private state
// (static = file-local linkage; invisible to other translation units)

// ChaCha20 cipher object. The default constructor configures 20 rounds.
static ChaCha  s_chacha;

// One-block keystream cache.
// Refilled automatically when s_keystreamUsed >= CSPRNG_BLOCK_BYTES.
static uint8_t s_keystreamBuf[CSPRNG_BLOCK_BYTES];

// How many bytes of s_keystreamBuf have been consumed so far.
// Starts at CSPRNG_BLOCK_BYTES to trigger an immediate refill on first use.
static uint8_t s_keystreamUsed = CSPRNG_BLOCK_BYTES;

// Private helper

// s_fillKeystreamBlock — produce the next 64-byte ChaCha20 output block.
//
// Memory-efficient technique: zero the buffer in-place, then encrypt over it.
//   output[i] = input[i] ^ keystream[i] = 0x00 ^ keystream[i] = keystream[i]
//
// This avoids allocating a second 64-byte "zeros input" buffer in SRAM.
//
// ChaCha20's internal 64-bit block counter is advanced automatically by
// encrypt(), so each successive call produces a completely different block;
// the keystream never repeats within 2^64 blocks (an astronomically large
// volume for a microcontroller application).
static void s_fillKeystreamBlock() {
  // Zero the cache so the in-place XOR yields the raw keystream.
  memset(s_keystreamBuf, 0, CSPRNG_BLOCK_BYTES);

  // XOR the all-zero input with ChaCha20's keystream → raw keystream output.
  // The library advances its internal counter after every 64-byte call.
  s_chacha.encrypt(s_keystreamBuf, s_keystreamBuf, CSPRNG_BLOCK_BYTES);

  s_keystreamUsed = 0u;
}

// Public API

// initCSPRNG — seed ChaCha20 with 256 bits of hardware entropy.
//
// Parameters:
//   hardwareSeed — exactly 32 bytes produced by generateEntropyPool().
//                  The pointer is read once; the caller is responsible for
//                  scrubbing the seed buffer after this call.
//
// Key and nonce policy:
//   Key  = hardwareSeed (256 bits, unique per power-on cycle).
//   IV   = 0x00…0 (64 bits, zeroed deliberately).
//   A zero nonce is safe here because the key itself is non-repeating;
//   the (key, nonce) pair is unique across all sessions.
//
// Side effect:
//   Pre-fills s_keystreamBuf so the very first getSecureRandom32() call
//   returns immediately without any additional cipher invocation.
void initCSPRNG(const uint8_t* hardwareSeed) {
  // Install the 256-bit hardware-entropy key into the ChaCha20 engine.
  s_chacha.setKey(hardwareSeed, 32u);

  // Set a zero IV (nonce). Safe because the key is unique per session.
  // The IV is 8 bytes for djb-ChaCha (not the 12-byte IETF variant).
  static const uint8_t zeroIV[8] = {};
  s_chacha.setIV(zeroIV, sizeof(zeroIV));

  // Pre-compute the first keystream block so the first caller incurs no stall.
  s_fillKeystreamBlock();
}

// getSecureRandom32 — non-blocking; returns 32 bits of CSPRNG output.
//
// Normal cost: O(1) — four byte reads and one counter increment.
// Amortised refill cost: ~100 µs every 16 calls (once per 64-byte block).
//
// Byte assembly uses explicit shifts to avoid type-punning undefined
// behaviour (casting uint8_t* to uint32_t* is UB on strict-aliasing AVR ABI).
uint32_t getSecureRandom32() {
  // Transparently refill the cache when fewer than 4 bytes remain.
  if (s_keystreamUsed + 4u > CSPRNG_BLOCK_BYTES) {
    s_fillKeystreamBlock();
  }

  // Assemble four consecutive keystream bytes as a little-endian uint32_t.
  const uint32_t value =
       static_cast<uint32_t>(s_keystreamBuf[s_keystreamUsed])             |
      (static_cast<uint32_t>(s_keystreamBuf[s_keystreamUsed + 1u]) <<  8u) |
      (static_cast<uint32_t>(s_keystreamBuf[s_keystreamUsed + 2u]) << 16u) |
      (static_cast<uint32_t>(s_keystreamBuf[s_keystreamUsed + 3u]) << 24u);

  s_keystreamUsed += 4u;
  return value;
}
