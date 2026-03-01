#pragma once

#include <Arduino.h>
#include "protocol.h"

 
// RECEIVER (Node B) — "The Synthesizer"
// Knows nothing about the melody; holds only a universal frequency dictionary.
// Validates, decrypts each packet and plays the corresponding note.
 

// Hardware pins 
const uint8_t RX_BUZZER_PIN = 9;   // PWM-capable pin connected to the piezo speaker
const uint8_t RX_LCD_ADDR   = 0x27; // I2C address of the Aip31068 LCD

// Note dictionary size 
// The receiver's "universal dictionary" maps a note index to a frequency in Hz.
const uint8_t NOTE_DICT_SIZE = 16;

// Finite State Machine states 
// The entire RX logic is driven by this FSM; no blocking delays allowed.
enum class RxState : uint8_t {
  WAITING_FOR_START,   // Discarding bytes until 0xAA is found
  READING_PAYLOAD,     // Buffering bytes 1-4 of the incoming packet
  VALIDATING_CHECKSUM, // All 5 bytes received; verifying integrity
  EXECUTING_ACTION     // Checksum valid; decrypting payload and playing the note
};

// Public API 
void rx_setup();
void rx_loop();

// Packet processing helpers 
// Called from rx_loop() for every byte that arrives on the serial port.
// Drives the FSM forward based on the received byte.
void processReceivedByte(uint8_t inByte);

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
