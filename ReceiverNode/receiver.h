/**
 * @file receiver.h
 * @brief SH2SC-EDT — Receiver Node B ("The Synthesizer") public interface.
 * @details Part of the SH2SC-EDT project. Implements the C2P-ARQ protocol.
 *          Declares the RX FSM states, hardware pin constants, the universal
 *          note frequency dictionary, and all public functions used by
 *          ReceiverNode.ino.
 *          Node B has no knowledge of the melody structure — it holds only a
 *          universal frequency dictionary (universal_notes[21]) and authenticates
 *          and plays one note at a time as directed by Transmitter Node A.
 */

#pragma once

#include <Arduino.h>
#include "protocol.h"
#include "csprng.h"
#include <ChaChaPoly.h>

/**
 * @defgroup rx_hw_pins Receiver Hardware Pin Assignments
 * @{
 */
const uint8_t RX_BUZZER_PIN        = 9;    ///< PWM-capable pin connected to the piezo buzzer.
const uint8_t ENTROPY_RING_OSC_PIN = 2;    ///< Hardware ring oscillator entropy source (INT0).
const uint8_t RX_LCD_ADDR          = 0x3E; ///< I2C address of the Aip31068 16x2 LCD display.
const uint8_t RX_LCD_COLS          = 16;   ///< Number of columns on the RX LCD.
const uint8_t RX_LCD_ROWS          = 2;    ///< Number of rows on the RX LCD.
/** @} */ // end group rx_hw_pins

/**
 * @brief Size of the universal note frequency dictionary on RX.
 * @details Indices 0–20 cover the full chromatic range (C4…G#5) used by any
 *          melody TX may send. Index 255 (REST_INDEX) means silence.
 */
const uint8_t NOTE_DICT_SIZE = 21;

/**
 * @brief Byte-level parser Finite State Machine states for the C2P-ARQ Receiver (Node B).
 * @details The entire RX logic is driven by this FSM. No blocking delays are
 *          permitted; each state transition is handled in a single non-blocking
 *          pass through rx_loop(). A MAC failure or parser timeout triggers
 *          resetParser() which returns the FSM to WAITING_SYNC_1.
 *
 *          Canonical byte-parser lifecycle:
 *          @code
 *          WAITING_SYNC_1 -> WAITING_SYNC_2 -> WAITING_FOR_TYPE
 *            -> READING_HELLO -> GOT_HELLO
 *            -> READING_DATA  -> GOT_DATA -> EXECUTING_ACTION
 *            ^                                     |
 *            |______ resetParser() ________________|
 *                  (MAC fail | parser timeout)
 *          @endcode
 */
enum class RxState : uint8_t {
  WAITING_SYNC_1,   ///< Initial/reset state — scanning the UART stream for SYNC_BYTE_1 (0xAA).
  WAITING_SYNC_2,   ///< SYNC_BYTE_1 confirmed — waiting for SYNC_BYTE_2 (0x55).
  WAITING_FOR_TYPE, ///< Sync preamble complete — waiting for the frame @c flags byte.
  READING_HELLO,    ///< Accumulating the 12-byte nonce body of a HelloPacket into the RX buffer.
  READING_DATA,     ///< Accumulating the 14-byte body (seq_num + payload + mac) of a DataPacket.
  GOT_HELLO,        ///< Full HelloPacket buffered; processHelloBody() will be called by rx_loop().
  GOT_DATA,         ///< Full DataPacket buffered; authenticateAndPlay() will be called by rx_loop().
  EXECUTING_ACTION  ///< MAC verified; note is sounding — non-blocking timer wait for note end.
};

/**
 * @brief Initialise RX hardware and seed the CSPRNG. Called once from setup().
 * @note Must be called once from Arduino @c setup().
 */
void rx_setup();

/**
 * @brief Execute one non-blocking C2P-ARQ FSM tick for the Receiver node.
 * @details Reads bytes from the UART, drives processReceivedByte(), dispatches
 *          packet handlers (processHelloBody(), authenticateAndPlay(),
 *          processFinPacket()), and manages the Dynamic Smart Watchdog timer.
 *          Each invocation performs at most one FSM transition and returns
 *          immediately — no @c delay() calls are permitted.
 * @note Must be called repeatedly from Arduino @c loop().
 */
void rx_loop();

/**
 * @brief Consume one incoming UART byte and advance the frame-assembly FSM.
 * @details Implements the byte-level parser FSM:
 *          WAITING_SYNC_1 -> WAITING_SYNC_2 -> WAITING_FOR_TYPE -> READING_HELLO/READING_DATA.
 *          On buffer completion transitions to GOT_HELLO or GOT_DATA for processing
 *          in the next rx_loop() pass.
 * @param inByte Byte just received from the UART hardware buffer.
 */
void processReceivedByte(uint8_t inByte);

/**
 * @brief Handle a fully buffered HelloPacket (FLAG_SYN) from the Transmitter.
 * @details Copies the received 12-byte nonce into @c s_sessionNonce, calls
 *          @c s_cipher.setKey(MASTER_PSK, 32) to pre-install the key, and sends
 *          @c ACK_BYTE on the feedback channel. Also arms the Dynamic Smart
 *          Watchdog with the default @c current_timeout_limit = 5000 ms.
 * @note Called from rx_loop() when the state is @c RxState::GOT_HELLO.
 */
void processHelloBody();

/**
 * @brief Authenticate and decrypt a DataPacket (FLAG_DAT); play the note on MAC success.
 * @details Full ChaCha20-Poly1305 AEAD pipeline:
 *          1. Read @c seq_num directly from @c pkt->seq_num (uint16_t, packed struct).
 *          2. Derive per-packet nonce: local copy of @c s_sessionNonce, then
 *             @c packetNonce[10] ^= (seq_num >> 8), @c packetNonce[11] ^= seq_num.
 *          3. @c clear() -> @c setKey(MASTER_PSK, 32) -> @c setIV(packetNonce, 12).
 *          4. @c addAuthData({flags, seq_lo, seq_hi}, 3) — 3-byte plaintext AAD.
 *          5. @c decrypt(pkt->payload, plaintext, DATA_PAYLOAD_SIZE).
 *          6. @c computeTag(expectedMac, 16), then @c memcmp(expectedMac, pkt->mac, TRUNCATED_MAC_SIZE).
 *
 *          **Security invariant:** startNote() is called ONLY after @c memcmp returns 0.
 *          A corrupted, replayed, or forged packet is always discarded at the MAC gate.
 *          Also validates @c noteIndex < NOTE_DICT_SIZE before accessing @c universal_notes[]
 *          to prevent out-of-bounds reads on ATmega328P.
 *
 * @param pkt Pointer to the fully buffered DataPacket in the RX buffer.
 */
void authenticateAndPlay(const DataPacket* pkt);

/**
 * @brief Authenticate a FLAG_FIN teardown packet and close the session on MAC success.
 * @details Runs the same full ChaChaPoly pipeline as authenticateAndPlay() using a
 *          @c discardBuf to receive the zero plaintext — the @c decrypt() call MUST
 *          execute before @c computeTag() to correctly advance the Poly1305 accumulator.
 *          On MAC success: sends ACK, erases @c s_sessionNonce via @c memset(),
 *          clears @c s_sessionActive, and resets the parser to @c WAITING_SYNC_1.
 *          On MAC failure: sends NACK and leaves the session active for FIN retransmission.
 * @param pkt Pointer to the fully buffered DataPacket (with @c flags == FLAG_FIN).
 * @note Key erasure (@c memset) on MAC success is mandatory for forward secrecy.
 */
void processFinPacket(const DataPacket* pkt);

/**
 * @brief Reset the byte-parser FSM to WAITING_SYNC_1 and drain the UART RX FIFO.
 * @details Called on MAC failure or parser timeout to prevent a corrupted frame
 *          from also poisoning the boundary detection of the next frame.
 *          Drains any lingering bytes from the 64-byte hardware UART FIFO so the
 *          next successful 0xAA 0x55 preamble is genuinely the start of a new frame.
 */
void resetParser();

/**
 * @brief Start a non-blocking note playback on the piezo buzzer.
 * @details Calls @c tone(RX_BUZZER_PIN, frequencyHz), records the start timestamp,
 *          and stores @c durationMs so that rx_loop() can call stopNote() when
 *          the required time has elapsed. For @c REST_INDEX, @c noTone() is called
 *          immediately instead.
 * @param frequencyHz Frequency in Hz for @c tone() (e.g. 262 for middle C).
 *                    Pass 0 to produce a rest (silence).
 * @param durationMs  Duration in milliseconds to play the note.
 */
void startNote(uint16_t frequencyHz, uint16_t durationMs);

/**
 * @brief Stop the currently playing note by calling @c noTone().
 * @details Called by rx_loop() when (millis() - noteStartTime) >= noteDurationMs.
 *          Also updates the Dynamic Smart Watchdog timeout limit for the next note.
 */
void stopNote();

/**
 * @brief Refresh the RX LCD with the current FSM state and last packet result.
 * @details
 *          - Row 0: Human-readable RxState label.
 *          - Row 1: @c SEQ:<seqNum> OK  (MAC passed) or @c SEQ:<seqNum> MAC! (failed).
 *          Must only be called on FSM state transitions — NOT in a tight loop.
 * @param state  Current @c RxState to display on row 0.
 * @param seqNum Last received sequence number to display on row 1.
 * @param macOk  @c true if the last packet's MAC verification passed; @c false otherwise.
 */
void updateRxDisplay(RxState state, uint16_t seqNum, bool macOk);

/**
 * @brief Harvest 256 bits of hardware entropy and write them to @p outputSeed (RX variant).
 * @details Fills @c outputSeed[32] as 8 independent 32-bit words from six hardware sources
 *          (no human-timing jitter source since RX has no button):
 *          1. Ring oscillator on INT0 (pin 2): pulse count over a 2 ms gate window.
 *          2. Eight uninitialised SRAM bytes at @c 0x0100 + wordIndex*8.
 *          3. On-die temperature ADC (channel 8, 1.1 V reference): 8 LSBs per word.
 *          4. TCNT1 free-running timer snapshot (2 bytes).
 *          5. A0 white-noise ADC: 8 LSBs per word.
 *          6. Arduino software PRNG @c random() (obfuscation layer).
 *
 *          Total harvest time: ~8 × 2 ms gate = ~16 ms (one-shot cost in setup()).
 *
 * @param outputSeed Pointer to a 32-byte buffer that will receive the entropy pool.
 *                   Pass directly to initCSPRNG(); scrub afterwards if desired.
 * @note Invoke once during rx_setup(), before the UART receive loop starts.
 */
void generateEntropyPool(uint8_t* outputSeed);
