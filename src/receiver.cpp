// RECEIVER (Node B) — "The Synthesizer"
// Flash this sketch onto the RX Arduino Nano.

// Current responsibilities:
//   - Initialise UART (9600) and I2C LCD (Aip31068).
//   - Hold the universal note-frequency dictionary (indices 0–20).
//   - Collect incoming bytes non-blocking into rx_buffer[5].
//   - validateAndDecrypt(): verify checksum, send ACK/NACK, decrypt, play note.
//   - Non-blocking buzzer timing via millis().

#include "../include/receiver.h"
#include <LiquidCrystal_I2C.h>

// UNIVERSAL NOTE FREQUENCY DICTIONARY
//
// "universal_notes" maps an encoded note index (sent by TX) to the actual
// frequency in Hz that the buzzer must produce. The receiver never knows which
// melody is playing — it only knows how to translate index → frequency.
//
// Index layout (chromatic scale, C4 … G#5):
//   0=C4  1=C#4  2=D4  3=D#4  4=E4   5=F4   6=F#4  7=G4
//   8=G#4 9=A4  10=A#4 11=B4  12=C5  13=C#5 14=D5  15=D#5
//  16=E5  17=F5  18=F#5 19=G5  20=G#5
static const uint16_t universal_notes[NOTE_DICT_SIZE] = {
  262,  //  0 — C4
  277,  //  1 — C#4
  294,  //  2 — D4
  311,  //  3 — D#4
  330,  //  4 — E4
  349,  //  5 — F4
  370,  //  6 — F#4
  392,  //  7 — G4
  415,  //  8 — G#4
  440,  //  9 — A4
  466,  // 10 — A#4
  494,  // 11 — B4
  523,  // 12 — C5
  554,  // 13 — C#5
  587,  // 14 — D5
  622,  // 15 — D#5
  659,  // 16 — E5
  698,  // 17 — F5
  740,  // 18 — F#5
  784,  // 19 — G5
  831   // 20 — G#5
};

// HARDWARE OBJECTS

// I2C LCD: 16 columns × 2 rows, Aip31068-compatible via LiquidCrystal_I2C.
static LiquidCrystal_I2C lcd(RX_LCD_ADDR, RX_LCD_COLS, RX_LCD_ROWS);

// RUNTIME STATE

static RxState currentState  = RxState::WAITING_FOR_START;

// Static receive buffer — exactly PACKET_SIZE bytes, no heap allocation.
static uint8_t rx_buffer[PACKET_SIZE];
static uint8_t bytesReceived = 0; // How many bytes have been written into rx_buffer

// Non-blocking note playback timer.
static uint32_t noteStartMs  = 0;    // millis() timestamp when the note began
static uint16_t noteLengthMs = 0;    // How long the note should sound
static bool     isPlayingNote = false;

// DISPLAY HELPER
// Updates the LCD only when called explicitly — never in a busy-loop.
void updateRxDisplay(RxState state, uint8_t seqNum, bool checksumOk) {
  lcd.clear();

  // Row 0: FSM state label
  lcd.setCursor(0, 0);
  switch (state) {
    case RxState::WAITING_FOR_START:   lcd.print("WAIT START");  break;
    case RxState::READING_PAYLOAD:     lcd.print("READING...");  break;
    case RxState::GOT_PACKET:          lcd.print("Got Packet");  break;
    case RxState::VALIDATING_CHECKSUM: lcd.print("VALIDATING");  break;
    case RxState::EXECUTING_ACTION:    lcd.print("PLAYING");     break;
  }

  // Row 1: sequence number — shown only after at least one packet has arrived
  lcd.setCursor(0, 1);
  if (state != RxState::WAITING_FOR_START && state != RxState::READING_PAYLOAD) {
    lcd.print("SEQ:");
    lcd.print(seqNum);
    lcd.print(checksumOk ? " OK" : " ---");
  }
}

// BYTE PROCESSOR — drives the FSM one byte at a time
// Called from rx_loop() for every byte that arrives on the serial port.
// Non-blocking by design: only processes bytes already in the HW UART buffer.
void processReceivedByte(uint8_t inByte) {
  switch (currentState) {

    case RxState::WAITING_FOR_START:
      // Any byte that is not the frame delimiter is noise — silently discard.
      // This keeps the buffer clean even in the presence of channel corruption.
      if (inByte == START_MARKER) {
        rx_buffer[PACKET_IDX_START] = inByte;
        bytesReceived = 1;
        currentState  = RxState::READING_PAYLOAD;
      }
      break;

    case RxState::READING_PAYLOAD:
      // Collect bytes 1–4 into the static buffer one at a time.
      rx_buffer[bytesReceived] = inByte;
      bytesReceived++;

      if (bytesReceived == PACKET_SIZE) {
        // All 5 bytes are in the buffer — hand control to rx_loop().
        currentState = RxState::GOT_PACKET;
      }
      break;

    // Remaining states are resolved in rx_loop(), not here.
    default:
      break;
  }
}

// CRYPTO & INTEGRITY FUNCTIONS

// validateChecksum — verifies the XOR frame integrity.
// Recomputes CHK_expected = B0^B1^B2^B3 and compares with packet[4].
// Returns true when the received frame is intact.
bool validateChecksum(const uint8_t packet[PACKET_SIZE]) {
  const uint8_t expected = packet[PACKET_IDX_START]
                         ^ packet[PACKET_IDX_NOTE]
                         ^ packet[PACKET_IDX_DURATION]
                         ^ packet[PACKET_IDX_SEQ];
  return (expected == packet[PACKET_IDX_CHECKSUM]);
}

// validateAndDecrypt — the main RX crypto pipeline entry point.
//
// Workflow (mirrors the TX pipeline from 05_encryption_approach.instructions.md):
//   1. Compute CHK_expected = B0^B1^B2^B3; compare with buffer[4].
//   2. FAIL: send NACK_BYTE, return {0, 0, false}.
//   3. PASS: send ACK_BYTE.
//   4. Reconstruct K_dynamic = SECRET_KEY ^ buffer[PACKET_IDX_SEQ].
//   5. Decrypt: noteIndex    = buffer[PACKET_IDX_NOTE]     ^ K_dynamic  (M = C ^ K)
//               durationTens = buffer[PACKET_IDX_DURATION] ^ K_dynamic
//   6. Bounds-check noteIndex against NOTE_DICT_SIZE.
//   7. Look up frequency in universal_notes[], call startNote().
//   8. Return filled DecryptedNote struct.
DecryptedNote validateAndDecrypt(uint8_t* buffer) {
  DecryptedNote result = {0, 0, false};

  // Step 1-2: integrity check
  if (!validateChecksum(buffer)) {
    // Packet was corrupted by channel noise — request a retransmission.
    Serial.write(NACK_BYTE);
    return result; // isValid stays false
  }

  // Step 3: acknowledge clean packet
  Serial.write(ACK_BYTE);

  // Step 4: reconstruct the same dynamic key TX used for this packet
  // K_dynamic = SECRET_KEY ^ seq_num  (changes every packet → no replay attacks)
  const uint8_t seqNumber = buffer[PACKET_IDX_SEQ];
  const uint8_t key       = SECRET_KEY ^ seqNumber;

  // Step 5: XOR decryption (M = C ^ K_dynamic)
  const uint8_t noteIndex    = buffer[PACKET_IDX_NOTE]     ^ key;
  const uint8_t durationTens = buffer[PACKET_IDX_DURATION] ^ key;

  // Step 6: bounds check — guard against out-of-range index
  if (noteIndex >= NOTE_DICT_SIZE) {
    // Packet passed checksum but contains an invalid note index.
    // This should not happen in normal operation; skip playback silently.
    result.isValid = false;
    return result;
  }

  // Step 7: look up frequency and trigger non-blocking playback ---
  const uint16_t frequencyHz = universal_notes[noteIndex];
  const uint16_t durationMs  = static_cast<uint16_t>(durationTens) * 10u;
  startNote(frequencyHz, durationMs);

  // Step 8: return decoded data for display / diagnostics ---
  result.noteIndex    = noteIndex;
  result.durationMs10 = durationTens;
  result.isValid      = true;
  return result;
}

// startNote — begins buzzer output; non-blocking.
// tone() configures the PWM hardware and returns immediately.
// The note is silenced by stopNote() called from rx_loop() via millis().
void startNote(uint16_t frequencyHz, uint16_t durationMs) {
  tone(RX_BUZZER_PIN, frequencyHz);
  noteStartMs   = millis();
  noteLengthMs  = durationMs;
  isPlayingNote = true;
}

// stopNote — silences the buzzer.
void stopNote() {
  noTone(RX_BUZZER_PIN);
  isPlayingNote = false;
}

// decryptAndPlay — kept for API compatibility; delegates to validateAndDecrypt.
void decryptAndPlay(const uint8_t packet[PACKET_SIZE]) {
  validateAndDecrypt(const_cast<uint8_t*>(packet));
}

 
// ARDUINO ENTRY POINTS
 

void rx_setup() {
  // UART: 9600 8N1 — must match the transmitter exactly.
  Serial.begin(BAUD_RATE);

  // Buzzer pin configured as output; stays silent until a valid note arrives.
  pinMode(RX_BUZZER_PIN, OUTPUT);

  // I2C LCD (Aip31068 compatible, address 0x27).
  lcd.init();
  lcd.backlight();

  // Reset FSM and buffer.
  currentState  = RxState::WAITING_FOR_START;
  bytesReceived = 0;

  updateRxDisplay(currentState, 0, false);
}

void rx_loop() {
  // Non-blocking note duration management
  // Once the note has been sounding for its full duration, silence the buzzer.
  // No delay() used: the comparison is O(1) and returns instantly.
  if (isPlayingNote && ((millis() - noteStartMs) >= noteLengthMs)) {
    stopNote();
  }

  // Non-blocking UART reading
  // Read as many bytes as are waiting in the hardware UART buffer right now.
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    processReceivedByte(inByte);
  }

  // Resolve GOT_PACKET
  // All 5 bytes are buffered; run the full validation + decryption pipeline.
  if (currentState == RxState::GOT_PACKET) {
    const DecryptedNote note = validateAndDecrypt(rx_buffer);

    // Update the display with the outcome regardless of validity.
    updateRxDisplay(
      note.isValid ? RxState::EXECUTING_ACTION : RxState::WAITING_FOR_START,
      rx_buffer[PACKET_IDX_SEQ],
      note.isValid
    );

    // Reset the buffer so the FSM is ready for the next incoming packet.
    bytesReceived = 0;
    currentState  = RxState::WAITING_FOR_START;
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
