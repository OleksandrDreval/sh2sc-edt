#pragma once

#include <Arduino.h>
#include "protocol.h"

 
// TRANSMITTER (Node A) — "The Conductor"
// Stores the melody, encrypts and sends 5-byte packets, awaits ACK/NACK.
 

// Hardware pins 
const uint8_t  TX_BUTTON_PIN    = 2;     // Tactile start button (INPUT_PULLUP)
const uint8_t  TX_LCD_ADDR      = 0x3E;  // I2C address of the Aip31068 LCD
const uint8_t  TX_LCD_COLS      = 16;
const uint8_t  TX_LCD_ROWS      = 2;

// Button debounce 
const uint16_t DEBOUNCE_DELAY_MS = 50;   // Milliseconds a signal must be stable

// Finite State Machine states 
// The entire TX logic is driven by this FSM; no blocking delays allowed.
enum class TxState : uint8_t {
  IDLE,        // Waiting for button press to start melody playback
  SENDING,     // Forming, encrypting and transmitting the current packet
  WAITING_ACK  // Packet sent; listening on the feedback line for ACK or NACK
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
void sendPacket(uint8_t noteIndex, uint8_t noteDuration, uint8_t seqNum);

// High-level send entry point used by the FSM SENDING state.
// Takes raw (plain-text) note_idx and duration_idx, stores them as
// the pending retransmit payload, then delegates to sendPacket().
// The module-level seqNum is consumed automatically.
void formAndSendPacket(uint8_t note_idx, uint8_t duration_idx);

// Display helper 
// Updates the I2C LCD with the current FSM state, sequence number and checksum.
// Must never call lcd.clear() in a tight loop — only on state changes.
void updateTxDisplay(TxState state, uint8_t seqNum, uint8_t checksum);
