// RECEIVER (Node B) — "The Synthesizer"
// Flash this sketch onto the RX Arduino Nano.

// Current responsibilities:
//   - Initialise UART (9600) and I2C LCD (Aip31068).
//   - Hold the universal note-frequency dictionary (indices 0–20).
//   - Collect incoming bytes non-blocking into rx_buffer[5].
//   - validateAndDecrypt(): verify checksum, send ACK/NACK, decrypt, play note.
//   - Non-blocking buzzer timing via millis().

#include "receiver.h"
#include <LiquidCrystal_AIP31068_I2C.h>

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

// I2C LCD: 16 columns × 2 rows, Aip31068-compatible controller.
static LiquidCrystal_AIP31068_I2C lcd(RX_LCD_ADDR, RX_LCD_COLS, RX_LCD_ROWS);

// RUNTIME STATE

static RxState currentState  = RxState::WAITING_FOR_START;

// Static receive buffer — exactly PACKET_SIZE bytes, no heap allocation.
static uint8_t rx_buffer[PACKET_SIZE];
static uint8_t bytesReceived = 0; // How many bytes have been written into rx_buffer

// Non-blocking note playback timer.
static uint32_t noteStartMs  = 0;    // millis() timestamp when the note began
static uint16_t noteLengthMs = 0;    // How long the note should sound
static bool     isPlayingNote = false;

// Non-blocking "CHK ERR! NACK" error-flash timer.
// When a corrupted packet arrives, the error message is shown for
// CHK_ERR_DISPLAY_MS milliseconds, then the display reverts to normal.
const uint16_t  CHK_ERR_DISPLAY_MS = 50;
static bool     isShowingError    = false;
static uint32_t errorDisplayStart = 0;

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
  const uint8_t noteIndex      = buffer[PACKET_IDX_NOTE]     ^ key;
  const uint8_t durationEncoded = buffer[PACKET_IDX_DURATION] ^ key;

  // Convert encoded duration unit back to milliseconds.
  // TX packed the value as (duration_ms / DURATION_UNIT_MS), so invert here.
  const uint16_t durationMs = static_cast<uint16_t>(durationEncoded) * DURATION_UNIT_MS;

  // Step 6a: handle REST/pause — valid packet, but buzzer must be silent.
  // Index 255 (REST_INDEX) is intentional silence, not a corruption artefact.
  if (noteIndex == REST_INDEX) {
    stopNote();  // Silence buzzer and clear the isPlayingNote flag.
    result.noteIndex    = REST_INDEX;
    result.durationMs10 = durationEncoded;
    result.isValid      = true;
    return result;
  }

  // Step 6b: bounds check — guard against truly out-of-range indices
  if (noteIndex >= NOTE_DICT_SIZE) {
    // Packet passed checksum but contains an invalid note index.
    // This should not happen in normal operation; skip playback silently.
    result.isValid = false;
    return result;
  }

  // Step 7: look up frequency and trigger non-blocking playback ---
  const uint16_t frequencyHz = universal_notes[noteIndex];
  startNote(frequencyHz, durationMs);

  // Step 8: return decoded data for display / diagnostics ---
  result.noteIndex    = noteIndex;
  result.durationMs10 = durationEncoded;
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

// ENTROPY POOL  (RX variant — no button, omits human-timing jitter)

// Pulse counter incremented by the ring oscillator ISR on pin 2 (INT0).
// volatile prevents the compiler from caching the value in a register.
static volatile uint32_t s_ringOscPulses = 0;
static void onRingOscPulse() { ++s_ringOscPulses; }

// mixEntropy — one step of the cryptographic sponge.
// Rotates the pool left by 1 bit, then XOR-folds in new entropy bits.
static inline uint32_t mixEntropy(uint32_t pool, uint32_t bits) {
  return ((pool << 1u) | (pool >> 31u)) ^ bits;
}

// generateEntropyPool (RX) — fills outputSeed[32] with 256 bits of entropy.
// The 32-byte output is structured as 8 independent 32-bit words.
// Each word is produced by a fresh pass over ALL six hardware sources.
//
// Total execution time: 8 iterations × 2 ms gate ≈ 16 ms (one-shot only).
void generateEntropyPool(uint8_t* outputSeed) {
  // SRAM base: 64 uninitialised bytes starting at 0x0100 on ATmega328P.
  // Each word consumes a distinct 8-byte slice so the slices never repeat.
  const uint8_t* sramBase = reinterpret_cast<const uint8_t*>(0x0100);

  for (uint8_t wordIndex = 0; wordIndex < 8u; ++wordIndex) {
    uint32_t pool = 0;

    // Source 1: Ring oscillator gate (pin 2, INT0) — fresh 2 ms window per word.
    s_ringOscPulses = 0;
    attachInterrupt(digitalPinToInterrupt(ENTROPY_RING_OSC_PIN),
                    onRingOscPulse, RISING);
    delay(2);
    detachInterrupt(digitalPinToInterrupt(ENTROPY_RING_OSC_PIN));
    pool = mixEntropy(pool, s_ringOscPulses);

    // Source 2: SRAM chaos — 8 unique bytes per word (slice: wordIndex*8 .. +7).
    for (uint8_t i = 0; i < 8u; ++i) {
      pool = mixEntropy(pool, sramBase[wordIndex * 8u + i]);
    }

    // Source 3: On-die temperature ADC (channel 8, 1.1 V ref) — 8 LSBs per word.
    {
      const uint8_t savedAdmux = ADMUX;
      ADMUX   = _BV(REFS1) | _BV(REFS0) | _BV(MUX3);  // 0xC8
      ADCSRA |= _BV(ADEN);
      // Discard first conversion after reference change
      ADCSRA |= _BV(ADSC); while (ADCSRA & _BV(ADSC)) {}
      uint8_t adcEntropy = 0;
      for (uint8_t i = 0; i < 8u; ++i) {
        ADCSRA |= _BV(ADSC); while (ADCSRA & _BV(ADSC)) {}
        adcEntropy = static_cast<uint8_t>((adcEntropy << 1u) | (ADCL & 0x01u));
      }
      pool  = mixEntropy(pool, adcEntropy);
      ADMUX = savedAdmux;
    }

    // Source 4: TCNT1 timer jitter — unique value at each iteration boundary.
    pool = mixEntropy(pool, static_cast<uint32_t>(TCNT1));

    // Source 5: A0 white noise generator — 8 LSBs per word.
    {
      uint8_t a0Entropy = 0;
      for (uint8_t i = 0; i < 8u; ++i) {
        a0Entropy = static_cast<uint8_t>(
            (a0Entropy << 1u) | (static_cast<uint8_t>(analogRead(A0)) & 0x01u)
        );
      }
      pool = mixEntropy(pool, a0Entropy);
    }

    // NOTE: micros() is intentionally absent on RX — no human input device.

    // Source 6: Arduino software PRNG (obfuscation layer).
    pool = mixEntropy(pool, static_cast<uint32_t>(random()));

    // Write the 32-bit word into the output seed as 4 bytes (little-endian).
    outputSeed[wordIndex * 4u + 0u] = static_cast<uint8_t>(pool);
    outputSeed[wordIndex * 4u + 1u] = static_cast<uint8_t>(pool >>  8u);
    outputSeed[wordIndex * 4u + 2u] = static_cast<uint8_t>(pool >> 16u);
    outputSeed[wordIndex * 4u + 3u] = static_cast<uint8_t>(pool >> 24u);
  }
}

 
// ARDUINO ENTRY POINTS
 

void rx_setup() {
  // UART: 9600 8N1 — must match the transmitter exactly.
  Serial.begin(BAUD_RATE);

  // Buzzer pin configured as output; stays silent until a valid note arrives.
  pinMode(RX_BUZZER_PIN, OUTPUT);

  // I2C LCD (Aip31068 compatible, address 0x27).
  lcd.init();
  // lcd.backlight();

  // Reset FSM and buffer.
  currentState  = RxState::WAITING_FOR_START;
  bytesReceived = 0;

  updateRxDisplay(currentState, 0, false);

  // Harvest 256-bit hardware entropy and seed the ChaCha20 CSPRNG.
  // ~16 ms total (8 ring-oscillator gate windows of 2 ms each) — one-time cost.
  // The seed is scrubbed from the stack immediately after handing it to the cipher.
  {
    uint8_t entropySeed[32];
    generateEntropyPool(entropySeed);
    initCSPRNG(entropySeed);
    memset(entropySeed, 0, sizeof(entropySeed));
  }

  // ENTROPY TEST (remove after validation)
  // Harvest entropy immediately after hardware init so SRAM chaos bytes retain
  // their power-on state and the ring oscillator has a fresh count window.
//{  uint8_t seedBuf[32];
//   generateEntropyPool(seedBuf);
//   // Display first 4 bytes (word 0) as hex for quick visual check.
//   const uint32_t previewWord =
//       (static_cast<uint32_t>(seedBuf[3]) << 24u) |
//       (static_cast<uint32_t>(seedBuf[2]) << 16u) |
//       (static_cast<uint32_t>(seedBuf[1]) <<  8u) |
//        static_cast<uint32_t>(seedBuf[0]);
//   lcd.clear();
//   lcd.setCursor(0, 0);
//   lcd.print("RX KEY:");
//   lcd.setCursor(0, 1);
//   lcd.print(previewWord, HEX);  // e.g. "5D8E0F41"
//   delay(3000);                  // Hold result on screen for 3 s
//   lcd.clear();
//   updateRxDisplay(currentState, 0, false);
//}
  // END ENTROPY TEST
}

void rx_loop() {
  // Error-flash expiry: once CHK_ERR_DISPLAY_MS have elapsed, restore the
  // normal WAITING_FOR_START display — fully non-blocking.
  if (isShowingError && ((millis() - errorDisplayStart) >= CHK_ERR_DISPLAY_MS)) {
    isShowingError = false;
    updateRxDisplay(RxState::WAITING_FOR_START, 0, false);
  }

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

  // Resolve GOT_PACKET — validate integrity, send ACK/NACK, decrypt, play.
  //
  // FSM path on SUCCESS:  GOT_PACKET → VALIDATING_CHECKSUM → EXECUTING_ACTION → WAITING_FOR_START
  // FSM path on FAILURE:  GOT_PACKET → VALIDATING_CHECKSUM → WAITING_FOR_START
  if (currentState == RxState::GOT_PACKET) {
    currentState = RxState::VALIDATING_CHECKSUM;

    const DecryptedNote note = validateAndDecrypt(rx_buffer);
    // ACK_BYTE (0x06) or NACK_BYTE (0x15) is already sent inside validateAndDecrypt.

    if (note.isValid) {
      // Checksum passed → tone() has been triggered inside startNote().
      currentState = RxState::EXECUTING_ACTION;
      updateRxDisplay(currentState, rx_buffer[PACKET_IDX_SEQ], true);
    } else {
      // Checksum failed → NACK sent, TX will retransmit.
      // Flash "CHK ERR! NACK" for CHK_ERR_DISPLAY_MS ms and then revert — non-blocking.
      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("CHK ERR! NACK");
      lcd.setCursor(0, 1);
      lcd.print("SEQ:");
      lcd.print(rx_buffer[PACKET_IDX_SEQ]);
      errorDisplayStart = millis();
      isShowingError    = true;
    }

    // Always reset the buffer so the FSM is ready for the next incoming packet.
    bytesReceived = 0;
    currentState  = RxState::WAITING_FOR_START;
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
