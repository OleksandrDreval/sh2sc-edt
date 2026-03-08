/**
 * @file csprng.h
 * @brief ChaCha20-based CSPRNG for SH2SC-EDT — Transmitter Node A (ATmega328P).
 * @details Part of the SH2SC-EDT project. Implements the C2P-ARQ protocol.
 *
 *          This module wraps the ChaCha20 stream cipher as a Cryptographically
 *          Secure Pseudo-Random Number Generator (CSPRNG) for the ATmega328P.
 *          The cipher is seeded once with 256 bits of hardware entropy collected
 *          by generateEntropyPool(), then used as an unlimited deterministic
 *          keystream to produce session nonces.
 *
 *          Mathematical basis:
 *          @code
 *          C = P XOR KS  ->  C = 0x00..0 XOR KS = KS
 *          @endcode
 *          Encrypting an all-zeros plaintext yields the raw ChaCha20 keystream.
 *
 *          **Buffer design (AVR memory optimisation):**
 *          ChaCha20 generates output in 64-byte blocks. Invoking the cipher for
 *          every byte would be prohibitively expensive on an 8-bit MCU, so this
 *          module maintains a 64-byte keystream cache. getSecureRandom32() draws
 *          4 bytes per call; the block is refilled every 16 calls (~100 us at
 *          16 MHz).
 *
 *          **Static SRAM budget (approximate):**
 *          - s_chacha object: ~140 bytes (ChaCha20 key schedule + state)
 *          - s_keystreamBuf:    64 bytes
 *          - s_keystreamUsed:    1 byte
 *          - Total:           ~205 bytes of 2048 bytes available
 *
 *          **Requires:** Arduino Crypto library by Rhys Weatherley.
 *          Library Manager: "Crypto" by Rhys Weatherley.
 *
 *          **Usage:**
 *          1. Call initCSPRNG(seed) ONCE in setup() after generateEntropyPool().
 *          2. Call getSecureRandom32() anywhere in the main loop for 32-bit random output.
 */

#pragma once

#include <Arduino.h>
#include <ChaCha.h>

/**
 * @brief Size of one ChaCha20 keystream output block in bytes.
 * @details Must be a multiple of 4 so that getSecureRandom32() never straddles
 *          a block boundary. One block = 64 bytes = 512 bits.
 */
static const uint8_t CSPRNG_BLOCK_BYTES = 64u;

/// @brief ChaCha20 cipher object (20-round configuration by default constructor).
static ChaCha  s_chacha;

/// @brief One-block keystream cache. Refilled automatically when @c s_keystreamUsed >= CSPRNG_BLOCK_BYTES.
static uint8_t s_keystreamBuf[CSPRNG_BLOCK_BYTES];

/**
 * @brief Number of bytes consumed from @c s_keystreamBuf so far.
 * @details Initialised to @c CSPRNG_BLOCK_BYTES to trigger an immediate refill
 *          on the very first call to getSecureRandom32().
 */
static uint8_t s_keystreamUsed = CSPRNG_BLOCK_BYTES;

/**
 * @brief Produce the next 64-byte ChaCha20 keystream block into @c s_keystreamBuf.
 * @details Memory-efficient technique — zero the buffer in-place, then encrypt over it:
 *          @code
 *          output[i] = input[i] XOR keystream[i] = 0x00 XOR keystream[i] = keystream[i]
 *          @endcode
 *          This avoids allocating a second 64-byte "zeros input" buffer in SRAM.
 *          ChaCha20's internal 64-bit block counter is advanced automatically by
 *          encrypt(), so successive calls produce entirely distinct blocks; the
 *          keystream never repeats within 2^64 blocks.
 */
static void s_fillKeystreamBlock() {
  // Zero the cache so the in-place XOR yields the raw keystream.
  memset(s_keystreamBuf, 0, CSPRNG_BLOCK_BYTES);

  // XOR the all-zero input with ChaCha20's keystream -> raw keystream output.
  // The library advances its internal block counter after every 64-byte call.
  s_chacha.encrypt(s_keystreamBuf, s_keystreamBuf, CSPRNG_BLOCK_BYTES);

  s_keystreamUsed = 0u;
}

/**
 * @brief Seed the ChaCha20 CSPRNG with 256 bits of hardware entropy.
 * @details Key and nonce policy:
 *          - Key = hardwareSeed (256 bits, unique per power-on cycle).
 *          - IV  = 0x00..0 (8 bytes, zeroed deliberately).
 *          A zero nonce is safe because the key itself is non-repeating;
 *          the (key, nonce) pair is globally unique across all sessions.
 *
 *          Pre-fills @c s_keystreamBuf so the very first getSecureRandom32()
 *          call returns immediately without an additional cipher invocation.
 *
 * @param hardwareSeed Pointer to exactly 32 bytes produced by generateEntropyPool().
 *                     The pointer is read once; the caller is responsible for
 *                     scrubbing the seed buffer after this call if desired.
 * @note Must be called ONCE in setup() after generateEntropyPool() completes.
 */
void initCSPRNG(const uint8_t* hardwareSeed) {
  // Install the 256-bit hardware-entropy key into the ChaCha20 engine.
  s_chacha.setKey(hardwareSeed, 32u);

  // Set a zero IV (nonce). Safe because the key is unique per session.
  // The IV is 8 bytes for djb-ChaCha (not the 12-byte IETF variant used for packets).
  static const uint8_t zeroIV[8] = {};
  s_chacha.setIV(zeroIV, sizeof(zeroIV));

  // Pre-compute the first keystream block so the first caller incurs no stall.
  s_fillKeystreamBlock();
}

/**
 * @brief Return 32 bits of CSPRNG output (non-blocking).
 * @details Normal cost: O(1) — four byte reads and one counter increment.
 *          Amortised refill cost: ~100 us every 16 calls (once per 64-byte block).
 *
 *          Byte assembly uses explicit shifts to avoid type-punning undefined
 *          behaviour; casting @c uint8_t* to @c uint32_t* is UB under the
 *          AVR strict-aliasing ABI.
 *
 * @return A 32-bit pseudo-random value drawn from the ChaCha20 keystream.
 */
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
