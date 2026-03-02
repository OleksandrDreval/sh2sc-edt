#pragma once

#include <Arduino.h>
#include "protocol.h"

 
// RECEIVER (Node B) — "The Synthesizer"
// Knows nothing about the melody; holds only a universal frequency dictionary.
// Validates, decrypts each packet and plays the corresponding note.
 

// Hardware pins 
const uint8_t RX_BUZZER_PIN         = 9;    // PWM-capable pin connected to the piezo speaker
const uint8_t ENTROPY_RING_OSC_PIN  = 2;    // Hardware ring oscillator (chaos source)
const uint8_t RX_LCD_ADDR           = 0x3E; // I2C address of the Aip31068 LCD

// Note dictionary size
// The receiver's "universal dictionary" maps a note index to a frequency in Hz.
// Indices 0-20 cover the full range of notes used by any melody the TX may send.
const uint8_t NOTE_DICT_SIZE = 21;

const uint8_t RX_LCD_COLS   = 16;
const uint8_t RX_LCD_ROWS   = 2;

// Finite State Machine states 
// The entire RX logic is driven by this FSM; no blocking delays allowed.
enum class RxState : uint8_t {
  WAITING_FOR_START,   // Discarding bytes until 0xAA is found
  READING_PAYLOAD,     // Buffering bytes 1-4 of the incoming packet
  GOT_PACKET,          // All 5 bytes collected; resolved in rx_loop()
  VALIDATING_CHECKSUM, // Checksum check in progress (Stage 3)
  EXECUTING_ACTION     // Checksum valid; decrypting payload and playing the note
};

// Public API 
void rx_setup();
void rx_loop();

// Packet processing helpers 
// Called from rx_loop() for every byte that arrives on the serial port.
// Drives the FSM forward based on the received byte.
void processReceivedByte(uint8_t inByte);

// Decoded payload returned by validateAndDecrypt().
// isValid == false means the checksum failed and the fields must not be used.
struct DecryptedNote {
  uint8_t noteIndex;    // Plain-text index into universal_notes[]
  uint8_t durationMs10; // Plain-text duration in tens of milliseconds
  bool    isValid;      // true only when the checksum matched
};

// Core validation + decryption function.
// 1. Recomputes CHK_expected = B0^B1^B2^B3 and compares with buffer[4].
// 2a. Mismatch → sends NACK_BYTE on Serial, returns {0, 0, false}.
// 2b. Match    → sends ACK_BYTE, decrypts both payload bytes via
//              K_dynamic = SECRET_KEY ^ seqNum, calls startNote(),
//              and returns the decoded data in a DecryptedNote struct.
DecryptedNote validateAndDecrypt(uint8_t* buffer);

// Recomputes the expected checksum from the received packet bytes and
// compares it to the transmitted checksum (packet[4]).
// Returns true if the packet is intact; false if corrupted by noise.
bool validateChecksum(const uint8_t packet[PACKET_SIZE]);

// Decrypts both payload bytes using the dynamic key derived from seq_num,
// looks up the frequency in the note dictionary and triggers tone playback.
void decryptAndPlay(const uint8_t packet[PACKET_SIZE]);

// Starts playing a note at the given frequency for durationMs milliseconds.
// Non-blocking: records the start time and relies on millis() for stop logic.
void startNote(uint16_t frequencyHz, uint16_t durationMs);

// Silences the buzzer; called by rx_loop() when the note duration has elapsed.
void stopNote();

// Display helper 
// Updates the I2C LCD with current FSM state and last received sequence number
// without blocking the main loop.
void updateRxDisplay(RxState state, uint8_t seqNum, bool checksumOk);

// Entropy pool generator (RX variant) 
// Harvests hardware entropy from four sources and folds them into a 32-bit nonce.
// Sources:
//   1. Ring oscillator on pin 2 (INT0): pulse count over a 2 ms gate window.
//   2. First 64 bytes of uninitialised SRAM (address 0x0100 on ATmega328P).
//   3. On-die temperature ADC (channel 8, 1.1 V ref): 8 LSBs from 8 conversions.
//   4. TCNT1 free-running timer snapshot.
// NOTE: RX has no button, so human-timing jitter (micros()) is intentionally omitted.
// Calling convention: invoke once during rx_setup() before the UART loop starts.
uint32_t generateEntropyPool();
