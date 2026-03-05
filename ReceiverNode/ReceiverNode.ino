// RECEIVER (Node B) — "The Synthesizer"
// Flash this sketch onto the RX Arduino Nano.

// Current responsibilities:
//   - Initialise UART (9600) and I2C LCD (Aip31068).
//   - Hold the universal note-frequency dictionary (indices 0–20).
//   - FSM: dispatch incoming bytes by packet_type (0x01 HELLO / 0x02 DATA).
//   - processHelloBody(): store session nonce, install MASTER_PSK key.
//   - authenticateAndPlay(): full ChaCha20-Poly1305 authenticated decryption;
//       memcmp(expected_mac, received_mac, 8) != 0 → NACK (note NEVER played); 0 → ACK + tone().
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

// 4-state byte-level FSM driving all serial parsing.
// WAIT_AA / WAIT_55 — preamble scan; both HELLO and DATA must start with 0xAA 0x55,
//   so no frame type can bypass the preamble gate.
// READ_TYPE    — store the packet_type byte into rx_buffer[0] and set expected_length.
// READ_PAYLOAD — collect (expected_length - 1) remaining bytes, then dispatch.
enum ParseState : uint8_t { WAIT_AA, WAIT_55, READ_TYPE, READ_PAYLOAD };
static ParseState parseState = WAIT_AA;

// rx_buffer is sized to hold a full DataPacket (15 bytes).
// HelloPacket (13 bytes) also fits.  rx_buffer[0] always holds packet_type.
// Casting rx_buffer to the appropriate struct* gives zero-copy struct access.
static uint8_t rx_buffer[sizeof(DataPacket)];
static uint8_t rx_index       = 0;  // Bytes collected in the current frame
static uint8_t expected_length = 0;  // Set in READ_TYPE; total bytes for this frame

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
const uint16_t  CHK_ERR_DISPLAY_MS    = 500;
static bool     isShowingError        = false;
static uint32_t errorDisplayStart     = 0;

// Parser timeout: if collection stalls for RX_PARSER_TIMEOUT_MS without a new
// byte, the partial frame is dropped and preamble scan restarts.
const uint16_t  RX_PARSER_TIMEOUT_MS = 20;
static uint32_t rxLastByteMs         = 0;

// Display state (for LCD only — independent of the parser FSM).
static RxState currentState = RxState::WAITING_SYNC_1;

// DISPLAY HELPER
void updateRxDisplay(RxState state, uint16_t seqNum, bool macOk) {
  lcd.clear();

  // Row 0: FSM state label
  lcd.setCursor(0, 0);
  switch (state) {
    case RxState::WAITING_SYNC_1:   lcd.print("WAIT SYNC");  break;
    case RxState::WAITING_SYNC_2:   lcd.print("WAIT SYNC2"); break;
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

// SELF-HEALING HELPERS

// resetParser — flush the hardware UART RX buffer and reset all FSM
// state to a clean WAITING_SYNC_1 baseline.
//
// When to call:
//   1. MAC failure (memcmp of truncated tag ≠ 0) — the buffer likely holds noise
//      bytes from the same burst that corrupted the current packet.
//   2. Parser timeout — a partial frame body was interrupted by a noise
//      burst long enough to stall byte delivery for RX_PARSER_TIMEOUT_MS.
//
// The Serial.flush() variant only flushes TX; to drain RX we read-and-discard
// every byte currently waiting in the 64-byte hardware FIFO.
static void resetParser() {
  // Drain any garbage in the 64-byte hardware UART RX FIFO.
  while (Serial.available() > 0) {
    Serial.read();
  }
  rx_index     = 0;
  parseState   = WAIT_AA;
  currentState = RxState::WAITING_SYNC_1;
}

// BYTE PROCESSOR — drives the parser FSM one byte at a time.
// All processing (crypto, note playback) happens inline here — rx_loop()
// only needs to check note-timer and error-display expiry.
void processReceivedByte(uint8_t inByte) {
  switch (parseState) {

    // Preamble scan
    // ALL packet types (HELLO and DATA) are now prefixed with 0xAA 0x55.
    // Nothing can enter the body-collection path without passing this gate.

    case WAIT_AA:
      if (inByte == SYNC_BYTE_1) {
        parseState = WAIT_55;
      }
      // Any other byte (including FLAG_SYN=0x01 without preamble) — channel noise, stay.
      break;

    case WAIT_55:
      if (inByte == SYNC_BYTE_2) {
        rx_index   = 0;
        parseState = READ_TYPE;
      } else if (inByte != SYNC_BYTE_1) {
        // If a second 0xAA arrives stay in WAIT_55 (overlapping preambles);
        // anything else means the preamble was corrupted — restart from WAIT_AA.
        parseState = WAIT_AA;
      }
      break;

    // Packet-type discriminator
    // Preamble confirmed.  The very next byte identifies the frame type and
    // determines expected_length so READ_PAYLOAD knows when to stop.

    case READ_TYPE:
      // Store the flags byte at offset 0 — it is the first field of both structs.
      // Use bitwise-AND (not ==) for matching: this tolerates future multi-flag
      // combinations and is slightly more noise-resilient than strict equality.
      rx_buffer[0] = inByte;
      rx_index     = 1;
      if (inByte & FLAG_SYN) {
        // SYN frame — HelloPacket (13 bytes): flags(1) + nonce(12).
        expected_length = static_cast<uint8_t>(sizeof(HelloPacket));  // 13
        parseState      = READ_PAYLOAD;
        currentState    = RxState::READING_HELLO;
        updateRxDisplay(currentState, 0, false);
      } else if (inByte & FLAG_DAT) {
        // DAT frame — DataPacket (15 bytes): flags(1) + seq_num(2) + payload(4) + mac(8).
        expected_length = static_cast<uint8_t>(sizeof(DataPacket));   // 15
        parseState      = READ_PAYLOAD;
        currentState    = RxState::READING_DATA;
      } else if (inByte & FLAG_FIN) {
        // FIN frame — reserved for session-close (Етап 2/3).
        // Treated as a DataPacket-sized frame for now; authenticateAndPlay()
        // will NACK it once FLAG_FIN handling is added.
        expected_length = static_cast<uint8_t>(sizeof(DataPacket));   // 15
        parseState      = READ_PAYLOAD;
        currentState    = RxState::READING_DATA;
      } else {
        // No recognised flag bit — channel noise, restart preamble scan.
        rx_index   = 0;
        parseState = WAIT_AA;
      }
      break;

    // Body collection
    // Accumulate bytes until the full frame is in rx_buffer, then dispatch.
    // rx_buffer[0] = packet_type, rx_buffer[1..] = rest of the struct.

    case READ_PAYLOAD: {
      rx_buffer[rx_index++] = inByte;
      if (rx_index == expected_length) {
        if (rx_buffer[0] & FLAG_SYN) {
          // SYN frame complete — processHelloBody() reads nonce from rx_buffer[1..12].
          processHelloBody();
          currentState = RxState::WAITING_SYNC_1;
          updateRxDisplay(currentState, 0, false);
        } else if (rx_buffer[0] & FLAG_DAT) {
          // DAT frame — authenticate and play the note.
          const DataPacket* pkt = reinterpret_cast<const DataPacket*>(rx_buffer);
          if (s_sessionActive) {
            authenticateAndPlay(pkt);
          } else {
            // No session key yet — reject and request a new HELLO.
            Serial.write(NACK_BYTE);
          }
        } else if (rx_buffer[0] & FLAG_FIN) {
          // FIN frame — verify MAC, send ACK, erase session key.
          const DataPacket* pkt = reinterpret_cast<const DataPacket*>(rx_buffer);
          if (s_sessionActive) {
            processFinPacket(pkt);
          } else {
            // No active session — nothing to tear down, reset silently.
            resetParser();
          }
        } else {
          // No recognised flag — should not reach here; noise guard.
          resetParser();
        }
        // Return to preamble scan regardless of the dispatch outcome.
        rx_index   = 0;
        parseState = WAIT_AA;
      }
      break;
    }
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
// Calling convention: invoked directly from processReceivedByte() once HELLO nonce is complete.
void processHelloBody() {
  // rx_buffer[0]     = flags byte (FLAG_SYN confirmed in READ_PAYLOAD dispatch).
  // rx_buffer[1..12] = 12-byte CSPRNG nonce from TX sendHelloPacket().
  memcpy(s_sessionNonce, &rx_buffer[1], HELLO_NONCE_SIZE);

  // Pre-install the key so that per-packet handling only needs setIV().
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);

  s_sessionActive = true;

  // Confirm to TX that the nonce was received and the session key is armed.
  // Without this ACK, TX's WAITING_HELLO_ACK state would always time out
  // and keep retransmitting a new HelloPacket on every cycle.
  Serial.write(ACK_BYTE);
}

// authenticateAndPlay — full ChaCha20-Poly1305 v2 RX pipeline.
//
// Receives a pointer to the DataPacket cast directly from rx_buffer.
// Using the packed struct eliminates all manual byte-offset arithmetic and
// ensures byte order matches the TX-side struct exactly (#pragma pack(push, 1)).
//
// Security invariant: startNote() is called ONLY after MAC verification passes.
void authenticateAndPlay(const DataPacket* pkt) {
  const uint16_t seqNum = pkt->seq_num;  // Direct struct field — no manual shift/OR

  // Step 1 — Derive per-packet nonce via memcpy to protect the shared s_sessionNonce.
  // NEVER XOR directly into s_sessionNonce: that would corrupt every subsequent
  // packet's IV derivation.  Use a local copy as the TX side does.
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[10] ^= static_cast<uint8_t>((seqNum >> 8u) & 0xFFu);
  packetNonce[11] ^= static_cast<uint8_t>(seqNum         & 0xFFu);

  // Step 2 — 3-byte AAD: flags + both bytes of seq_num.
  // Must match the TX construction in sendPacket() byte-for-byte.
  // pkt->flags is used directly — any tamper to the flags byte fails MAC.
  const uint8_t aad[3] = {
    pkt->flags,
    static_cast<uint8_t>(seqNum         & 0xFFu),  // seq_num low byte
    static_cast<uint8_t>((seqNum >> 8u) & 0xFFu)   // seq_num high byte
  };

  // Step 3 — Configure cipher for this specific packet.
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);
  s_cipher.setIV(packetNonce, HELLO_NONCE_SIZE);
  s_cipher.addAuthData(aad, sizeof(aad));

  // Step 4 — Decrypt 4-byte payload (uint16_t[2]) in one pass.
  // decrypt() feeds ciphertext into Poly1305 AND XORs with keystream simultaneously.
  uint16_t plaintext[2];  // [0]=note_index, [1]=duration_ms
  s_cipher.decrypt(
    reinterpret_cast<uint8_t*>(plaintext),
    reinterpret_cast<const uint8_t*>(pkt->payload),
    DATA_PAYLOAD_SIZE
  );

  // CRITICAL Step 5 — Verify truncated (8-byte) Poly1305 MAC.
  // computeTag() + memcmp() replaces checkTag() because the library's
  // checkTag() requires the full 16-byte tag, not our 8-byte truncated one.
  uint8_t expectedMac[16];
  s_cipher.computeTag(expectedMac, 16u);

  if (memcmp(expectedMac, pkt->mac, TRUNCATED_MAC_SIZE) != 0) {
    // MAC mismatch: noise corruption or forgery.
    // Flush UART FIFO — burst that corrupted this packet likely left more garbage.
    resetParser();
    Serial.write(NACK_BYTE);
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("MAC FAIL! NACK");
    lcd.setCursor(0, 1);
    lcd.print("SEQ:");
    lcd.print(seqNum);
    errorDisplayStart = millis();
    isShowingError    = true;
    return;  // Discard — do NOT play any note.
  }

  // Step 6 — Authentication PASSED. Send ACK.
  Serial.write(ACK_BYTE);

  // Step 7 — Extract decoded fields.
  // payload fields are uint16_t; duration is direct milliseconds (no scaling).
  const uint16_t noteIndex  = plaintext[0];
  const uint16_t durationMs = plaintext[1];

  // Step 8 — Play note or REST.
  if (noteIndex == REST_INDEX) {
    stopNote();
  } else if (noteIndex < NOTE_DICT_SIZE) {
    startNote(universal_notes[noteIndex], durationMs);
  }
  // noteIndex out of range with a valid MAC: ignore (should never happen).

  currentState = RxState::EXECUTING_ACTION;
  updateRxDisplay(currentState, seqNum, true);
}

// processFinPacket — authenticate and process a FLAG_FIN session-teardown packet.
//
// Cryptographic pipeline is identical to authenticateAndPlay() to guarantee
// that only the legitimate TX (with knowledge of MASTER_PSK and s_sessionNonce)
// can produce a verifiable FIN.  A noise-generated FLAG_FIN byte will always
// fail MAC verification and trigger NACK without touching the session state.
//
// On MAC success: ACK sent, LCD updated, s_sessionNonce zeroed, parser reset.
// On MAC failure: NACK sent, LCD shows error, parser reset.
void processFinPacket(const DataPacket* pkt) {
  const uint16_t seqNum = pkt->seq_num;

  // Step 1 — Derive per-packet nonce (same derivation as TX sendFinPacket()).
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[10] ^= static_cast<uint8_t>((seqNum >> 8u) & 0xFFu);
  packetNonce[11] ^= static_cast<uint8_t>(seqNum         & 0xFFu);

  // Step 2 — 3-byte AAD: FLAG_FIN + seq_num bytes.
  // Must match TX sendFinPacket() byte-for-byte; any mismatch fails MAC.
  const uint8_t aad[3] = {
    FLAG_FIN,
    static_cast<uint8_t>(seqNum         & 0xFFu),
    static_cast<uint8_t>((seqNum >> 8u) & 0xFFu)
  };

  // Step 3 — Configure cipher.
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);
  s_cipher.setIV(packetNonce, HELLO_NONCE_SIZE);
  s_cipher.addAuthData(aad, sizeof(aad));

  // Step 4 — Decrypt 4-byte payload into a local discard buffer.
  // TX encrypts zeros; we decrypt to feed the Poly1305 state correctly.
  uint8_t discardBuf[DATA_PAYLOAD_SIZE];
  s_cipher.decrypt(
    discardBuf,
    reinterpret_cast<const uint8_t*>(pkt->payload),
    DATA_PAYLOAD_SIZE
  );

  // Step 5 — Verify truncated (8-byte) MAC.
  uint8_t expectedMac[16];
  s_cipher.computeTag(expectedMac, 16u);

  if (memcmp(expectedMac, pkt->mac, TRUNCATED_MAC_SIZE) != 0) {
    // MAC mismatch — noise or injection; do NOT close the session.
    Serial.write(NACK_BYTE);
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("FIN MAC FAIL!");
    lcd.setCursor(0, 1);
    lcd.print("NACK sent");
    resetParser();
    return;
  }

  // Step 6 — Authentication passed; confirm to TX.
  Serial.write(ACK_BYTE);

  // Step 7 — Display session-closed message for the operator.
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("SESSION CLOSED");
  lcd.setCursor(0, 1);
  lcd.print("SEQ:");
  lcd.print(seqNum);

  // Step 8 — CRITICAL: erase the session nonce from RAM.
  // With the nonce gone, no future packet can be decrypted even if
  // an attacker replays captured ciphertext or triggers a reset.
  memset(s_sessionNonce, 0, HELLO_NONCE_SIZE);
  s_sessionActive = false;

  // Step 9 — Return parser to clean idle state, ready for the next SYN.
  resetParser();
}

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

  // Reset parser and buffer — start at sync preamble acquisition.
  parseState   = WAIT_AA;
  rx_index     = 0;
  currentState = RxState::WAITING_SYNC_1;

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
    updateRxDisplay(RxState::WAITING_SYNC_1, 0, false);
  }

  // Non-blocking note duration management.
  if (isPlayingNote && ((millis() - noteStartMs) >= noteLengthMs)) {
    stopNote();
    if (currentState == RxState::EXECUTING_ACTION) {
      currentState = RxState::WAITING_SYNC_1;
      updateRxDisplay(currentState, 0, false);
    }
  }

  // Non-blocking UART reading.
  // processReceivedByte() handles all parsing, crypto, and playback inline;
  // rx_loop() only needs to run the timer callbacks above.
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    rxLastByteMs = millis();
    processReceivedByte(inByte);
  }

  // PARSER TIMEOUT — self-healing against mid-packet desync.
  // If bytes are being collected (rx_index > 0) but no new byte has arrived
  // for RX_PARSER_TIMEOUT_MS ms, the frame was torn apart by a noise burst.
  // Reset so the next 0xAA 0x55 preamble starts a fresh frame.
  if (rx_index > 0 && parseState != WAIT_AA &&
      (millis() - rxLastByteMs) >= RX_PARSER_TIMEOUT_MS) {
    resetParser();
    updateRxDisplay(RxState::WAITING_SYNC_1, 0, false);
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
