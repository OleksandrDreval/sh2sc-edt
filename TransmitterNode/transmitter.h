/**
 * @file transmitter.h
 * @brief SH2SC-EDT — Transmitter Node A ("The Conductor") public interface.
 * @details Part of the SH2SC-EDT project. Implements the C2P-ARQ protocol.
 *          Declares the TX FSM states, hardware pin constants, ARQ timing
 *          constants, and all public functions used by TransmitterNode.ino.
 *          Stores the melody in PROGMEM, encrypts packets via ChaCha20-Poly1305,
 *          and drives the full C2P-ARQ session lifecycle (SYN -> DAT -> FIN).
 */

#pragma once

#include <Arduino.h>
#include "protocol.h"
#include "csprng.h"
#include <ChaChaPoly.h>

/**
 * @defgroup tx_hw_pins Transmitter Hardware Pin Assignments
 * @{
 */
const uint8_t  TX_BUTTON_PIN        = 3;    ///< Tactile start button (INPUT_PULLUP, active LOW).
const uint8_t  ENTROPY_RING_OSC_PIN = 2;    ///< Hardware ring oscillator entropy source (INT0).
const uint8_t  TX_LCD_ADDR          = 0x3E; ///< I2C address of the Aip31068 16x2 LCD display.
const uint8_t  TX_LCD_COLS          = 16;   ///< Number of columns on the TX LCD.
const uint8_t  TX_LCD_ROWS          = 2;    ///< Number of rows on the TX LCD.
/** @} */ // end group tx_hw_pins

/**
 * @defgroup tx_timing Transmitter Timing Constants
 * @{
 */
const uint16_t DEBOUNCE_DELAY_MS     = 50;   ///< Minimum stable signal duration (ms) for button debounce.
/// Auto-reconnect HelloPacket broadcast interval (ms) while in RECONNECTING state.
const uint32_t RECONNECT_INTERVAL_MS = 2000;
/** @} */ // end group tx_timing

/**
 * @brief Finite State Machine states for the C2P-ARQ Transmitter (Node A).
 * @details The entire TX logic is driven by this FSM. No blocking delays
 *          are permitted; each state transition is handled in a single
 *          non-blocking pass through tx_loop().
 *
 *          Canonical lifecycle:
 *          @code
 *          IDLE -> SENDING_HELLO -> WAITING_HELLO_ACK -> SENDING
 *               -> WAITING_ACK -> WAIT_BETWEEN_NOTES -> SENDING_FIN
 *               -> WAITING_FIN_ACK
 *          (any WAITING_* + MAX_RETRIES exhausted) -> suspendSession() -> RECONNECTING
 *          RECONNECTING -> (HelloPacket ACK) -> SENDING  [Auto-Resume]
 *          @endcode
 *
 *          @mermaid
 *          stateDiagram-v2
 *              direction LR
 *              [*] --> IDLE
 *              IDLE --> SENDING_HELLO       : button press
 *              SENDING_HELLO --> WAITING_HELLO_ACK : HelloPacket sent
 *              WAITING_HELLO_ACK --> SENDING       : ACK received
 *              WAITING_HELLO_ACK --> RECONNECTING  : MAX_RETRIES exhausted
 *              SENDING --> WAITING_ACK             : DataPacket sent
 *              WAITING_ACK --> WAIT_BETWEEN_NOTES  : ACK received
 *              WAITING_ACK --> RECONNECTING        : MAX_RETRIES exhausted
 *              WAIT_BETWEEN_NOTES --> SENDING      : gap elapsed
 *              WAIT_BETWEEN_NOTES --> SENDING_FIN  : all notes done
 *              SENDING_FIN --> WAITING_FIN_ACK     : FIN packet sent
 *              WAITING_FIN_ACK --> IDLE            : ACK + nonce erased
 *              WAITING_FIN_ACK --> RECONNECTING    : MAX_RETRIES exhausted
 *              RECONNECTING --> SENDING_HELLO      : auto-ping every 2s (melodyIndex preserved)
 *          @endmermaid
 */
enum class TxState : uint8_t {
  IDLE,               ///< Waiting for a button press to begin melody playback.
  RECONNECTING,       ///< Link lost mid-melody; broadcasting HelloPackets every RECONNECT_INTERVAL_MS.
  SENDING_HELLO,      ///< Generating a CSPRNG nonce and transmitting the SYN handshake packet.
  WAITING_HELLO_ACK,  ///< HelloPacket sent; awaiting RX nonce-acceptance ACK.
  SENDING,            ///< Constructing, encrypting, and transmitting the current DataPacket.
  WAITING_ACK,        ///< DataPacket sent; listening on the feedback line for ACK or NACK.
  WAIT_BETWEEN_NOTES, ///< ACK received; holding the inter-note gap before advancing melodyIndex.
  SENDING_FIN,        ///< All notes delivered; transmitting the FLAG_FIN teardown packet.
  WAITING_FIN_ACK     ///< FIN packet sent; awaiting RX acknowledgement before erasing the session nonce.
};

/**
 * @brief Initialise TX hardware: UART, I2C LCD, button pin, ring-oscillator entropy.
 * @note Must be called once from Arduino @c setup().
 */
void tx_setup();

/**
 * @brief Execute one non-blocking FSM tick for the Transmitter node.
 * @details Dispatches to the handler for the current @c TxState. Each invocation
 *          performs at most one state transition and returns immediately — no
 *          @c delay() calls are permitted anywhere in this function or its callees.
 * @note Must be called repeatedly from Arduino @c loop().
 */
void tx_loop();

/**
 * @brief Suspend the current C2P-ARQ session and enter the Self-Healing reconnect loop.
 * @details Called automatically when @c retryCount reaches @c MAX_RETRIES in any
 *          @c WAITING_* FSM state. Performs the following operations:
 *          1. @c memset(s_sessionNonce, 0x00, HELLO_NONCE_SIZE) — erases the session
 *             nonce from RAM (forward secrecy; prevents key material leakage).
 *          2. Resets @c retryCount to 0.
 *          3. Preserves @c melodyIndex — the critical Self-Healing state that allows
 *             transmission to resume from the exact note of failure.
 *          4. Transitions the FSM to @c TxState::RECONNECTING.
 * @note The preserved @c melodyIndex is the defining "self-healing" property of SH2SC-EDT.
 */
void suspendSession();

/**
 * @brief Read and debounce the start button using a millis()-based filter.
 * @details Returns @c true exactly once per physical button press (falling edge
 *          on INPUT_PULLUP). Debounce window is @c DEBOUNCE_DELAY_MS milliseconds.
 * @return @c true on confirmed button press; @c false otherwise.
 */
bool readButtonPress();

/**
 * @brief Generate a fresh 12-byte CSPRNG session nonce and transmit it as a HelloPacket.
 * @details Calls @c getSecureRandom32() three times to fill @c s_sessionNonce[12],
 *          then broadcasts it in a FLAG_SYN HelloPacket preceded by the sync preamble
 *          (0xAA 0x55). Also calls @c drainRxFifo() before transmitting to discard
 *          any stale ACK/NACK bytes accumulated from prior noise bursts.
 *          The nonce is stored internally for use by subsequent sendPacket() calls.
 * @note Must be called ONCE per button press or per RECONNECTING attempt, before
 *       any sendPacket() call in the new session.
 */
void sendHelloPacket();

/**
 * @brief Encrypt and transmit a single DataPacket for the given note.
 * @details Derives the per-packet IV by copying @c s_sessionNonce and XOR-ing
 *          bytes 10–11 with the 16-bit @c seqNum, then runs the full ChaChaPoly
 *          pipeline:
 *          @code
 *          clear() -> setKey(MASTER_PSK, 32) -> setIV(packetNonce, 12)
 *          -> addAuthData({flags, seq_lo, seq_hi}, 3)
 *          -> encrypt(plaintext, ciphertext, DATA_PAYLOAD_SIZE)
 *          -> computeTag(fullMac, AUTH_TAG_SIZE)
 *          @endcode
 *          Only the first @c TRUNCATED_MAC_SIZE bytes of the tag are transmitted.
 *          Sends sync preamble (0xAA 0x55) + 15-byte DataPacket body (17 bytes total).
 * @param noteIndex    Note index to encrypt (0–20 for a pitch, REST_INDEX=255 for silence).
 * @param noteDurationMs Duration of the note in milliseconds (stored directly as uint16_t).
 * @param seqNum       16-bit packet sequence number; used for per-packet nonce derivation.
 */
void sendPacket(uint8_t noteIndex, uint16_t noteDurationMs, uint8_t seqNum);

/**
 * @brief High-level wrapper called by the SENDING FSM state.
 * @details Reads @c noteIndex and @c duration_ms from PROGMEM at the current
 *          @c melodyIndex, snapshots them into module-level retransmit variables,
 *          then delegates to sendPacket(). On NACK or timeout the FSM calls
 *          sendPacket() again directly (retransmit path reuses the snapshot).
 * @param note_idx     Note index loaded from the PROGMEM melody table.
 * @param duration_ms  Duration in milliseconds loaded from the PROGMEM melody table.
 */
void formAndSendPacket(uint8_t note_idx, uint16_t duration_ms);

/**
 * @brief Construct and transmit the FLAG_FIN session-close packet.
 * @details Cryptographically identical to sendPacket(): same per-packet nonce
 *          derivation (XOR bytes 10–11 with seqNum), same 3-byte AAD (flags +
 *          seq_num), same truncated Poly1305 MAC. The plaintext payload is
 *          all-zeros ({0, 0}) — the AEAD pipeline still runs in full.
 *          Called from @c SENDING_FIN state; retransmitted on NACK or timeout.
 * @note On successful FIN ACK, the caller must @c memset(s_sessionNonce, 0, 12)
 *       to complete the forward-secrecy teardown.
 */
void sendFinPacket();

/**
 * @brief Refresh the TX LCD with the current ARQ status and FSM state label.
 * @details
 *          - Row 0: @c PKT:<seqNum>  RTY:<retries>
 *          - Row 1: Human-readable FSM state label.
 *          Must be called only on FSM state transitions — NOT in a tight loop —
 *          to avoid I2C bus saturation.
 * @param state   Current @c TxState to display on row 1.
 * @param seqNum  Current packet sequence number to display on row 0.
 * @param retries Current consecutive retry count to display on row 0.
 */
void updateTxDisplay(TxState state, uint16_t seqNum, uint8_t retries);

/**
 * @brief Harvest 256 bits of hardware entropy and write them to @p outputSeed.
 * @details Fills @c outputSeed[32] (8 × 32-bit words) by XOR-combining seven
 *          independent entropy sources per word:
 *          1. Ring oscillator on INT0 (pin 2): pulse count over a 2 ms gate window.
 *          2. Eight uninitialised SRAM bytes at @c 0x0100 + wordIndex*8.
 *          3. On-die temperature ADC (channel 8, 1.1 V reference): 8 LSBs per word.
 *          4. TCNT1 free-running timer snapshot (2 bytes).
 *          5. A0 white-noise ADC: 8 LSBs per word.
 *          6. @c micros() at button-press time (human-timing jitter, TX-only source).
 *          7. Arduino software PRNG @c random() (obfuscation layer).
 *
 *          Total harvest time: ~8 × 2 ms gate = ~16 ms (acceptable one-shot cost).
 *
 * @param outputSeed Pointer to a 32-byte buffer that will receive the entropy pool.
 *                   Must be valid and writable. Caller should pass the buffer
 *                   directly to initCSPRNG() and then scrub it if desired.
 * @note Invoke once per button press, AFTER readButtonPress() returns @c true.
 */
void generateEntropyPool(uint8_t* outputSeed);
