#pragma once

#include <Arduino.h>
#include "protocol.h"

 
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

// Finite State Machine states 
// The entire TX logic is driven by this FSM; no blocking delays allowed.
enum class TxState : uint8_t {
  IDLE,                // Waiting for button press to start melody playback
  SENDING,             // Forming, encrypting and transmitting the current packet
  WAITING_ACK,         // Packet sent; listening on the feedback line for ACK or NACK
  WAIT_BETWEEN_NOTES   // ACK received; holding the inter-note pause before advancing
};

// Public API 
void tx_setup();
void tx_loop();

// Button helper (millis-based debounce) 
// Returns true once per physical button press (falling edge on INPUT_PULLUP).
bool readButtonPress();

// Packet construction helpers 
// Generates the dynamic encryption key for the given sequence number.
// Formula: K_dynamic = SECRET_KEY ^ seq_num
uint8_t generateDynamicKey(uint8_t seqNum);

// Computes the XOR checksum over the first four packet bytes (AFTER encryption).
// Formula: CHK = B0 ^ B1 ^ B2 ^ B3
uint8_t calculateChecksum(const uint8_t packet[PACKET_SIZE]);

// Low-level helper: encrypts both payload bytes, assembles the 5-byte frame
// and transmits it. Called by formAndSendPacket and on retransmissions.
// noteDurationMs is in real milliseconds; encoding to packet units happens here.
void sendPacket(uint8_t noteIndex, uint16_t noteDurationMs, uint8_t seqNum);

// High-level send entry point used by the FSM SENDING state.
// Takes raw (plain-text) note_idx and duration_ms (milliseconds), stores them as
// the pending retransmit payload, then delegates to sendPacket().
// The module-level seqNum is consumed automatically.
void formAndSendPacket(uint8_t note_idx, uint16_t duration_ms);

// Display helper 
// Row 0: current packet number (seqNum) + consecutive retry counter.
// Row 1: current FSM state label.
// Never call in a tight loop — only on FSM state transitions.
void updateTxDisplay(TxState state, uint8_t seqNum, uint8_t retries);

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
