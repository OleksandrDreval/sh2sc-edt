#pragma once

#include <Arduino.h>
#include "protocol.h"
#include "csprng.h"
#include <ChaChaPoly.h>

 
// TRANSMITTER (Node A) — "The Conductor"
// Stores the melody, encrypts and sends 5-byte packets, awaits ACK/NACK.
 

// Hardware pins 
const uint8_t  TX_BUTTON_PIN        = 3;     // Tactile start button (INPUT_PULLUP)
const uint8_t  ENTROPY_RING_OSC_PIN = 2;     // Hardware ring oscillator (chaos source)
const uint8_t  TX_LCD_ADDR          = 0x3E;  // I2C address of the Aip31068 LCD
const uint8_t  TX_LCD_COLS          = 16;
const uint8_t  TX_LCD_ROWS          = 2;

// Button debounce 
const uint16_t DEBOUNCE_DELAY_MS = 50;   // Milliseconds a signal must be stable

// Stop-and-Wait ARQ limits 
//
// MAX_RETRIES is defined in protocol.h (shared with RX).
// Prevents a runaway retry loop if RX loses power without sending FLAG_FIN.
const uint32_t RECONNECT_INTERVAL_MS = 2000;  // Auto-reconnect ping interval (ms)

// Finite State Machine states 
// The entire TX logic is driven by this FSM; no blocking delays allowed.
enum class TxState : uint8_t {
  IDLE,                // Waiting for button press to start melody playback
  RECONNECTING,        // Link lost mid-melody; auto-pinging RX every RECONNECT_INTERVAL_MS
  SENDING_HELLO,       // Generating nonce and broadcasting the SYN handshake
  WAITING_HELLO_ACK,   // SYN sent; waiting for RX to confirm the nonce
  SENDING,             // Forming, encrypting and transmitting the current packet
  WAITING_ACK,         // Packet sent; listening on the feedback line for ACK or NACK
  WAIT_BETWEEN_NOTES,  // ACK received; holding the inter-note pause before advancing
  SENDING_FIN,         // All notes delivered; transmitting the FLAG_FIN teardown packet
  WAITING_FIN_ACK      // FIN sent; waiting for RX acknowledgement before key erasure
};

// Public API 
void tx_setup();
void tx_loop();

// Session suspend / Auto-Resume 
// Called when retryCount hits MAX_RETRIES in any WAITING_* state.
// Erases the session nonce from RAM (forward-secrecy), preserves melodyIndex
// so transmission can resume from the point of failure, and enters RECONNECTING.
void suspendSession();

// Button helper (millis-based debounce) 
// Returns true once per physical button press (falling edge on INPUT_PULLUP).
bool readButtonPress();

// Packet construction helpers 
// Generates a fresh 12-byte session nonce via CSPRNG, broadcasts it in a
// HelloPacket, and stores the nonce internally for per-packet derivation.
// Must be called ONCE on every button press, before any sendPacket() call.
void sendHelloPacket();

// Derives the per-packet IV by copying the session nonce and XOR-ing the
// last byte with seqNum, then runs the full ChaChaPoly pipeline:
//   clear() → setKey(MASTER_PSK) → setIV(packetNonce) →
//   addAuthData({packet_type, seqNum}) → encrypt(payload) → computeTag(mac)
// noteDurationMs is in real milliseconds; encoding to packet units happens here.
void sendPacket(uint8_t noteIndex, uint16_t noteDurationMs, uint8_t seqNum);

// High-level entry point used by the FSM SENDING / WAITING_ACK states.
// Snapshots the plain-text payload (for retransmit) then delegates to sendPacket().
void formAndSendPacket(uint8_t note_idx, uint16_t duration_ms);

// Constructs and transmits a FLAG_FIN teardown packet.
// Cryptographically identical to sendPacket(): same nonce derivation, same
// 3-byte AAD (flags + seq_num), same truncated MAC — zero plaintext payload.
// Called from SENDING_FIN state; retransmitted on NACK or timeout.
void sendFinPacket();

// Display helper 
// Row 0: current packet number (seqNum) + consecutive retry counter.
// Row 1: current FSM state label.
// Never call in a tight loop — only on FSM state transitions.
void updateTxDisplay(TxState state, uint16_t seqNum, uint8_t retries);

// Entropy pool generator (TX variant) 
// Fills outputSeed[32] with 256 bits of harvested hardware entropy.
// Each of the 8 words is independently gathered from all 7 sources:
//   1. Ring oscillator on pin 2 (INT0): pulse count over a 2 ms gate window.
//   2. Eight uninitialised SRAM bytes (8 per word, window at 0x0100+wordIndex*8).
//   3. On-die temperature ADC (channel 8, 1.1 V ref): 8 LSBs per word.
//   4. TCNT1 free-running timer snapshot.
//   5. A0 white noise generator: 8 LSBs per word.
//   6. micros() at the moment of the button press (human-timing jitter, TX only).
//   7. Arduino software PRNG random() (obfuscation layer).
// Total harvest time ≈ 8 × 2 ms gate = ~16 ms — acceptable for a one-shot call.
// Calling convention: invoke once per button press, AFTER readButtonPress() fires.
void generateEntropyPool(uint8_t* outputSeed);
