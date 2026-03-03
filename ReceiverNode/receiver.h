#pragma once

#include <Arduino.h>
#include "protocol.h"
#include "csprng.h"
#include <ChaChaPoly.h>

 
// RECEIVER (Node B) — "The Synthesizer"
// Knows nothing about the melody; holds only a universal frequency dictionary.
// Validates, decrypts each packet and plays the corresponding note.
// Crypto: ChaCha20-Poly1305 with per-session nonce delivered via HelloPacket.
 

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
  WAITING_FOR_TYPE,   // Idle — waiting for the first byte of any packet (packet_type)
  READING_HELLO,      // Collecting the 12-byte nonce body of a HelloPacket
  READING_DATA,       // Collecting the 19-byte body of a DataPacket
  GOT_HELLO,          // Full HelloPacket buffered; resolved in rx_loop()
  GOT_DATA,           // Full DataPacket buffered; resolved in rx_loop()
  EXECUTING_ACTION    // MAC verified; note is sounding (non-blocking wait)
};

// Public API 
void rx_setup();
void rx_loop();

// Packet byte-level reception driver 
// Called from rx_loop() for every byte that arrives on the serial port.
// Dispatches on packet_type and fills rx_buffer with the remaining frame bytes.
void processReceivedByte(uint8_t inByte);

// HELLO handler — called from rx_loop() when GOT_HELLO is set.
// Copies the buffered nonce into s_sessionNonce and installs MASTER_PSK.
void processHelloBody();

// DATA handler — called from rx_loop() when GOT_DATA is set.
// Full ChaCha20-Poly1305 pipeline:
//   1. Derive packetNonce = s_sessionNonce, last byte ^= rx_buffer[0] (seq_num).
//   2. clear() → setKey(MASTER_PSK) → setIV(packetNonce).
//   3. addAuthData({packet_type, seq_num}).
//   4. decrypt(payload, 2 bytes).
//   5. checkTag(mac, 16) — CRITICAL: if false → NACK, discard; if true → ACK.
void authenticateAndPlay();

// Starts playing a note at the given frequency for durationMs milliseconds.
// Non-blocking: records the start time and relies on millis() for stop logic.
void startNote(uint16_t frequencyHz, uint16_t durationMs);

// Silences the buzzer; called by rx_loop() when the note duration has elapsed.
void stopNote();

// Display helper 
// Updates the I2C LCD with current FSM state and last received sequence number
// without blocking the main loop.
void updateRxDisplay(RxState state, uint8_t seqNum, bool macOk);

// Entropy pool generator (RX variant) 
// Fills outputSeed[32] with 256 bits of harvested hardware entropy.
// Each of the 8 words is independently gathered from all 6 sources:
//   1. Ring oscillator on pin 2 (INT0): pulse count over a 2 ms gate window.
//   2. Eight uninitialised SRAM bytes (8 per word, window at 0x0100+wordIndex*8).
//   3. On-die temperature ADC (channel 8, 1.1 V ref): 8 LSBs per word.
//   4. TCNT1 free-running timer snapshot.
//   5. A0 white noise generator: 8 LSBs per word.
//   6. Arduino software PRNG random() (obfuscation layer).
// NOTE: RX has no button, so human-timing jitter (micros()) is intentionally omitted.
// Calling convention: invoke once during rx_setup() before the UART loop starts.
void generateEntropyPool(uint8_t* outputSeed);
