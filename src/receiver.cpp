 
// RECEIVER (Node B) — "The Synthesizer"
// Flash this sketch onto the RX Arduino Nano.
 

#include "../include/receiver.h"
#include <LiquidCrystal_I2C.h>

// I2C LCD instance (16 columns, 2 rows) 
static LiquidCrystal_I2C lcd(RX_LCD_ADDR, 16, 2);

// Universal note frequency dictionary (Hz) 
// Node B holds only frequencies — it never knows which song is being played.
// The TX encodes a note as an index into this table; RX looks up the frequency.
static const uint16_t NOTE_FREQUENCIES[NOTE_DICT_SIZE] = {
  262,  // C4  (index  0)
  277,  // C#4 (index  1)
  294,  // D4  (index  2)
  311,  // D#4 (index  3)
  330,  // E4  (index  4)
  349,  // F4  (index  5)
  370,  // F#4 (index  6)
  392,  // G4  (index  7)
  415,  // G#4 (index  8)
  440,  // A4  (index  9)
  466,  // A#4 (index 10)
  494,  // B4  (index 11)
  523,  // C5  (index 12)
  554,  // C#5 (index 13)
  587,  // D5  (index 14)
  622   // D#5 (index 15)
};

// Runtime state 
static RxState  currentState  = RxState::WAITING_FOR_START;
static uint8_t  rxBuffer[PACKET_SIZE];  // Static receive buffer; no heap allocation
static uint8_t  bytesReceived = 0;      // How many bytes are in the buffer so far
static uint8_t  lastSeqNum    = 0;      // Last processed sequence number (for display)
static bool     lastChecksumOk = false;

// Note playback timer (non-blocking) 
static uint32_t noteStartMs  = 0;
static uint16_t noteLengthMs = 0;
static bool     isPlayingNote = false;

 
// PUBLIC API IMPLEMENTATION
 

bool validateChecksum(const uint8_t packet[PACKET_SIZE]) {
  // Recompute the checksum from the received bytes and compare with packet[4].
  // CHK_expected = B0 ^ B1 ^ B2 ^ B3
  const uint8_t expected = packet[PACKET_IDX_START]
                         ^ packet[PACKET_IDX_NOTE]
                         ^ packet[PACKET_IDX_DURATION]
                         ^ packet[PACKET_IDX_SEQ];
  return (expected == packet[PACKET_IDX_CHECKSUM]);
}

void decryptAndPlay(const uint8_t packet[PACKET_SIZE]) {
  // Reconstruct the same dynamic key the transmitter used for this packet.
  // Decryption is identical to encryption because XOR is its own inverse:
  //   M = C ^ K_dynamic
  const uint8_t seqNumber       = packet[PACKET_IDX_SEQ];
  const uint8_t key             = SECRET_KEY ^ seqNumber;

  const uint8_t noteIndex    = packet[PACKET_IDX_NOTE]     ^ key;
  const uint8_t durationTens = packet[PACKET_IDX_DURATION] ^ key;

  // Guard against out-of-bounds dictionary access
  if (noteIndex >= NOTE_DICT_SIZE) {
    return;
  }

  const uint16_t frequencyHz = NOTE_FREQUENCIES[noteIndex];
  const uint16_t durationMs  = static_cast<uint16_t>(durationTens) * 10u;

  startNote(frequencyHz, durationMs);
}

void startNote(uint16_t frequencyHz, uint16_t durationMs) {
  // tone() is non-blocking; the actual silence is handled in rx_loop()
  // via millis() comparison — no delay() is used here.
  tone(RX_BUZZER_PIN, frequencyHz);
  noteStartMs   = millis();
  noteLengthMs  = durationMs;
  isPlayingNote = true;
}

void stopNote() {
  noTone(RX_BUZZER_PIN);
  isPlayingNote = false;
}

void processReceivedByte(uint8_t inByte) {
  switch (currentState) {

    case RxState::WAITING_FOR_START:
      // Discard everything until a valid frame delimiter is found
      if (inByte == START_MARKER) {
        rxBuffer[PACKET_IDX_START] = inByte;
        bytesReceived = 1;
        currentState  = RxState::READING_PAYLOAD;
      }
      break;

    case RxState::READING_PAYLOAD:
      rxBuffer[bytesReceived++] = inByte;
      if (bytesReceived == PACKET_SIZE) {
        // All 5 bytes collected — move to validation
        currentState = RxState::VALIDATING_CHECKSUM;
      }
      break;

    // Note: VALIDATING_CHECKSUM and EXECUTING_ACTION are handled
    // synchronously in rx_loop() rather than here, because they
    // also involve sending a response byte back to the transmitter.
    default:
      break;
  }
}

void updateRxDisplay(RxState state, uint8_t seqNumber, bool checksumOk) {
  lcd.clear();

  // Row 0: FSM state label
  lcd.setCursor(0, 0);
  switch (state) {
    case RxState::WAITING_FOR_START:   lcd.print("WAIT START");  break;
    case RxState::READING_PAYLOAD:     lcd.print("READING...");  break;
    case RxState::VALIDATING_CHECKSUM: lcd.print("VALIDATING");  break;
    case RxState::EXECUTING_ACTION:    lcd.print("PLAYING");     break;
  }

  // Row 1: last sequence number and checksum result
  lcd.setCursor(0, 1);
  lcd.print("SEQ:");
  lcd.print(seqNumber);
  lcd.print(checksumOk ? " OK" : " ERR");
}

 
// ARDUINO ENTRY POINTS
 

void rx_setup() {
  Serial.begin(BAUD_RATE);

  pinMode(RX_BUZZER_PIN, OUTPUT);

  lcd.init();
  lcd.backlight();

  currentState  = RxState::WAITING_FOR_START;
  bytesReceived = 0;
  updateRxDisplay(currentState, 0, false);
}

void rx_loop() {
  // Non-blocking note duration management 
  // Once a note has been playing for its designated duration, silence the buzzer.
  if (isPlayingNote && ((millis() - noteStartMs) >= noteLengthMs)) {
    stopNote();
  }

  // Byte-by-byte FSM processing 
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    processReceivedByte(inByte);
  }

  // Resolve completed packet states 
  // These transitions are handled here (not inside processReceivedByte) so
  // we can send a serial response without re-entering the byte-processing path.
  if (currentState == RxState::VALIDATING_CHECKSUM) {
    lastSeqNum     = rxBuffer[PACKET_IDX_SEQ];
    lastChecksumOk = validateChecksum(rxBuffer);

    if (lastChecksumOk) {
      // Packet is intact — acknowledge and play the note
      Serial.write(ACK_BYTE);
      currentState = RxState::EXECUTING_ACTION;
      updateRxDisplay(currentState, lastSeqNum, true);
    } else {
      // Packet is corrupted by noise — request retransmission
      Serial.write(NACK_BYTE);
      bytesReceived = 0;
      currentState  = RxState::WAITING_FOR_START;
      updateRxDisplay(currentState, lastSeqNum, false);
    }
  }

  if (currentState == RxState::EXECUTING_ACTION) {
    decryptAndPlay(rxBuffer);
    bytesReceived = 0;
    currentState  = RxState::WAITING_FOR_START;
    updateRxDisplay(currentState, lastSeqNum, true);
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
