// RECEIVER (Node B) — "The Synthesizer"
// Flash this sketch onto the RX Arduino Nano.

// Current responsibilities:
//   - Initialise UART (9600) and I2C LCD (Aip31068).
//   - Hold the universal note-frequency dictionary (indices 0–20).
//   - FSM: dispatch incoming bytes by packet_type (0x01 HELLO / 0x02 DATA).
//   - processHelloBody(): store session nonce, install MASTER_PSK key.
//   - authenticateAndPlay(): full ChaCha20-Poly1305 authenticated decryption;
//       checkTag() == false → NACK (note NEVER played); true → ACK + tone().
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

static RxState currentState  = RxState::WAITING_FOR_TYPE;

// Receive buffer for the BODY of a packet (bytes after the packet_type byte).
// Maximum body size: DataPacket body = seq_num(1) + payload(2) + mac(16) = 19 bytes.
// HelloPacket body = nonce(12) bytes.  Buffer is sized for the larger case.
static const uint8_t RX_BUF_SIZE = 1u + DATA_PAYLOAD_SIZE + AUTH_TAG_SIZE; // 19
static uint8_t  rx_buffer[RX_BUF_SIZE];
static uint8_t  rx_bytesNeeded = 0;   // Countdown: how many body bytes still needed
static uint8_t  rx_bytesIn     = 0;   // How many body bytes collected so far

// Packet type byte of the frame currently being assembled.
static uint8_t  s_rxPacketType = 0;

// Session state — set after a valid HelloPacket is processed.
static bool     s_sessionActive = false;           // false until first HELLO received
static uint8_t  s_sessionNonce[HELLO_NONCE_SIZE];  // Base nonce from the last HelloPacket

// ChaCha20-Poly1305 cipher instance (re-initialised per DATA packet via clear()).
static ChaChaPoly s_cipher;

// Non-blocking note playback timer.
static uint32_t noteStartMs  = 0;    // millis() timestamp when the note began
static uint16_t noteLengthMs = 0;    // How long the note should sound
static bool     isPlayingNote = false;

// Non-blocking MAC error display timer.
const uint16_t  CHK_ERR_DISPLAY_MS = 500;
static bool     isShowingError    = false;
static uint32_t errorDisplayStart = 0;

// DISPLAY HELPER
void updateRxDisplay(RxState state, uint8_t seqNum, bool macOk) {
  lcd.clear();

  // Row 0: FSM state label
  lcd.setCursor(0, 0);
  switch (state) {
    case RxState::WAITING_FOR_TYPE: lcd.print(s_sessionActive ? "READY" : "NO KEY"); break;
    case RxState::READING_HELLO:    lcd.print("HANDSHAKE");  break;
    case RxState::READING_DATA:     lcd.print("READING..."); break;
    case RxState::GOT_HELLO:        lcd.print("KEY SET");    break;
    case RxState::GOT_DATA:         lcd.print("VERIFYING");  break;
    case RxState::EXECUTING_ACTION: lcd.print("PLAYING");    break;
  }

  // Row 1: sequence number — shown only after at least one packet has been processed
  lcd.setCursor(0, 1);
  if (state == RxState::EXECUTING_ACTION || state == RxState::GOT_DATA) {
    lcd.print("SEQ:");
    lcd.print(seqNum);
    lcd.print(macOk ? " OK" : " MAC!");
  }
}

// BYTE PROCESSOR — drives the FSM one byte at a time
// Called from rx_loop() for every byte that arrives on the serial port.
// Non-blocking by design: only processes bytes already in the HW UART buffer.
void processReceivedByte(uint8_t inByte) {
  switch (currentState) {

    case RxState::WAITING_FOR_TYPE:
      // The very first byte of any frame is the packet_type discriminator.
      // All other bytes at this stage are channel noise — silently discard.
      if (inByte == PACKET_TYPE_HELLO) {
        s_rxPacketType = PACKET_TYPE_HELLO;
        rx_bytesNeeded = HELLO_NONCE_SIZE;  // 12 nonce bytes to follow
        rx_bytesIn     = 0;
        currentState   = RxState::READING_HELLO;
        updateRxDisplay(currentState, 0, false);
      } else if (inByte == PACKET_TYPE_DATA) {
        // Gate DATA packets on session readiness: refuse if no HELLO seen yet.
        if (!s_sessionActive) {
          // Cannot authenticate without a session nonce — send NACK and wait.
          Serial.write(NACK_BYTE);
          break;
        }
        s_rxPacketType = PACKET_TYPE_DATA;
        // Body layout: seq_num(1) + payload[2] + mac[16] = 19 bytes total.
        rx_bytesNeeded = 1u + DATA_PAYLOAD_SIZE + AUTH_TAG_SIZE;
        rx_bytesIn     = 0;
        currentState   = RxState::READING_DATA;
      }
      // Any other first byte is noise — remain in WAITING_FOR_TYPE.
      break;

    case RxState::READING_HELLO:
      rx_buffer[rx_bytesIn++] = inByte;
      if (rx_bytesIn == rx_bytesNeeded) {
        currentState = RxState::GOT_HELLO;
      }
      break;

    case RxState::READING_DATA:
      rx_buffer[rx_bytesIn++] = inByte;
      if (rx_bytesIn == rx_bytesNeeded) {
        currentState = RxState::GOT_DATA;
      }
      break;

    // GOT_HELLO, GOT_DATA and EXECUTING_ACTION are resolved in rx_loop().
    default:
      break;
  }
}

// CRYPTO & AUTHENTICATION FUNCTIONS

// processHelloBody — store session nonce and arm the cipher key.
//
// After this call:
//   • s_sessionNonce holds the 12-byte CSPRNG nonce from TX.
//   • MASTER_PSK is installed in s_cipher (setKey only — no IV yet).
//   • s_sessionActive = true — DATA packets will now be accepted.
//
// Calling convention: invoke from rx_loop() exactly once per GOT_HELLO event.
void processHelloBody() {
  // rx_buffer[0..11] = nonce delivered inside the HelloPacket.
  memcpy(s_sessionNonce, rx_buffer, HELLO_NONCE_SIZE);

  // Pre-install the key so that per-packet handling only needs setIV().
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);

  s_sessionActive = true;
}

// authenticateAndPlay — full ChaCha20-Poly1305 RX pipeline.
//
// rx_buffer layout (set by processReceivedByte in READING_DATA state):
//   rx_buffer[0]          — seq_num   (open header; part of AAD)
//   rx_buffer[1..2]       — payload[2] (ChaCha20 ciphertext: note, duration)
//   rx_buffer[3..18]      — mac[16]   (Poly1305 authentication tag)
//
// Security invariant: startNote() is called ONLY after checkTag() returns true.
// A false tag means the frame was corrupted or forged; NACK is sent, no sound.
void authenticateAndPlay() {
  const uint8_t seqNum          = rx_buffer[0];
  const uint8_t* ciphertext     = &rx_buffer[1];
  const uint8_t* receivedMac    = &rx_buffer[1u + DATA_PAYLOAD_SIZE]; // &rx_buffer[3]

  // Step 1 — Derive the per-packet IV.
  // Base: s_sessionNonce (12 bytes received in HelloPacket).
  // Modification: XOR the last byte with seqNum.
  // This mirrors the TX derivation exactly; both sides get the same IV
  // from only the public seqNum and the shared secret session nonce.
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[HELLO_NONCE_SIZE - 1u] ^= seqNum;

  // Step 2 — AAD: the two open (unauthenticated-but-bound) header bytes.
  // Any tampering with packet_type or seq_num will cause checkTag() to fail.
  const uint8_t aad[2] = { PACKET_TYPE_DATA, seqNum };

  // Step 3 — Configure cipher for this specific packet.
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);
  s_cipher.setIV(packetNonce, HELLO_NONCE_SIZE);
  s_cipher.addAuthData(aad, sizeof(aad));

  // Step 4 — Decrypt payload (2 bytes: note_index, duration_encoded).
  // decrypt() XORs ciphertext with the ChaCha20 keystream AND feeds the
  // ciphertext into the Poly1305 state — both operations happen in one pass.
  uint8_t plaintext[DATA_PAYLOAD_SIZE];
  s_cipher.decrypt(plaintext, ciphertext, DATA_PAYLOAD_SIZE);

  // CRITICAL Step 5 — Verify the Poly1305 authentication tag.
  // checkTag() compares the internally computed tag against the received one
  // in constant time to prevent timing side-channels.
  // If the tag does not match: the packet was corrupted by noise or forged.
  // Under no circumstances may the note be played before this check passes.
  if (!s_cipher.checkTag(receivedMac, AUTH_TAG_SIZE)) {
    Serial.write(NACK_BYTE);  // Request retransmission.
    // Flash MAC error on LCD for CHK_ERR_DISPLAY_MS ms (non-blocking).
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("MAC FAIL! NACK");
    lcd.setCursor(0, 1);
    lcd.print("SEQ:");
    lcd.print(seqNum);
    errorDisplayStart = millis();
    isShowingError    = true;
    return; // Discard — do NOT proceed to tone playback.
  }

  // Step 6 — Authentication PASSED.  Send ACK before playing.
  Serial.write(ACK_BYTE);

  // Step 7 — Decode plain-text fields.
  const uint8_t  noteIndex       = plaintext[0];
  const uint8_t  durationEncoded = plaintext[1];
  const uint16_t durationMs      = static_cast<uint16_t>(durationEncoded) * DURATION_UNIT_MS;

  // Step 8 — Handle REST (silence) vs. audible note.
  if (noteIndex == REST_INDEX) {
    stopNote();  // Ensure buzzer is silenced for the duration of the rest.
  } else if (noteIndex < NOTE_DICT_SIZE) {
    startNote(universal_notes[noteIndex], durationMs);
  }
  // If noteIndex is out of range but MAC was valid (should never happen with
  // a cooperative TX), silently skip to avoid undefined behaviour on the array.

  updateRxDisplay(RxState::EXECUTING_ACTION, seqNum, true);
}

// BUZZER HELPERS

// startNote — begins buzzer output; non-blocking.
// tone() configures the PWM hardware and returns immediately.
// The note is silenced by stopNote() which is called from rx_loop() via millis().
void startNote(uint16_t frequencyHz, uint16_t durationMs) {
  tone(RX_BUZZER_PIN, frequencyHz);
  noteStartMs   = millis();
  noteLengthMs  = durationMs;
  isPlayingNote = true;
}

// stopNote — silences the buzzer and clears the playback flag.
void stopNote() {
  noTone(RX_BUZZER_PIN);
  isPlayingNote = false;
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
  currentState   = RxState::WAITING_FOR_TYPE;
  rx_bytesIn     = 0;
  rx_bytesNeeded = 0;

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
  // MAC error-flash expiry: restore normal display after CHK_ERR_DISPLAY_MS ms.
  if (isShowingError && ((millis() - errorDisplayStart) >= CHK_ERR_DISPLAY_MS)) {
    isShowingError = false;
    updateRxDisplay(RxState::WAITING_FOR_TYPE, 0, false);
  }

  // Non-blocking note duration management.
  if (isPlayingNote && ((millis() - noteStartMs) >= noteLengthMs)) {
    stopNote();
    // Return to idle once the note has finished sounding.
    if (currentState == RxState::EXECUTING_ACTION) {
      currentState = RxState::WAITING_FOR_TYPE;
      updateRxDisplay(currentState, 0, false);
    }
  }

  // Non-blocking UART reading.
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    processReceivedByte(inByte);
  }

  // GOT_HELLO — install session nonce and key, then resume listening.
  if (currentState == RxState::GOT_HELLO) {
    currentState = RxState::GOT_HELLO;  // keep for display
    updateRxDisplay(RxState::GOT_HELLO, 0, false);

    processHelloBody();

    // Reset buffer and return to top-level dispatch.
    rx_bytesIn     = 0;
    rx_bytesNeeded = 0;
    currentState   = RxState::WAITING_FOR_TYPE;
    updateRxDisplay(currentState, 0, false);
  }

  // GOT_DATA — authenticate + decrypt + play (or NACK on MAC failure).
  //
  // FSM path SUCCESS: GOT_DATA → EXECUTING_ACTION → WAITING_FOR_TYPE (after note)
  // FSM path FAILURE: GOT_DATA → WAITING_FOR_TYPE  (immediately, NACK sent)
  if (currentState == RxState::GOT_DATA) {
    authenticateAndPlay();
    // authenticateAndPlay() either:
    //   a) called startNote() + updateRxDisplay(EXECUTING_ACTION) → state stays until note ends
    //   b) sent NACK and returned early → we must reset to WAITING_FOR_TYPE here
    if (!isPlayingNote) {
      // Auth failed (NACK path) or it was a REST — reset immediately.
      rx_bytesIn     = 0;
      rx_bytesNeeded = 0;
      currentState   = RxState::WAITING_FOR_TYPE;
    } else {
      // Auth succeeded — stay in EXECUTING_ACTION until note finishes.
      currentState = RxState::EXECUTING_ACTION;
      rx_bytesIn     = 0;
      rx_bytesNeeded = 0;
    }
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
