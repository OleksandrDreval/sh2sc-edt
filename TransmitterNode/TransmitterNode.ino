// TRANSMITTER (Node A) — "The Conductor"
// Flash this sketch onto the TX Arduino Nano.
//
// Responsibilities:
//   - Read the start button (with millis-based debounce on pin 3).
//   - Walk through the Super Mario melody array packet by packet.
//   - sendHelloPacket(): generate CSPRNG nonce → broadcast HelloPacket.
//   - sendPacket(): full ChaCha20-Poly1305 pipeline (nonce derivation →
//     encrypt → authenticate → transmit 20-byte DataPacket).
//   - Stop-and-Wait ARQ: after every SEND wait up to ACK_TIMEOUT_MS (50 ms) for ACK.
//     ACK  → advance melody (melodyIndex++, seqNum++).
//     NACK or timeout → retransmit the SAME packet with the SAME seqNum.
 

#include "transmitter.h"
#include "melody.h"
#include <LiquidCrystal_AIP31068_I2C.h>

 
// HARDWARE OBJECTS
 

// I2C LCD: 16 columns × 2 rows, Aip31068-compatible controller.
static LiquidCrystal_AIP31068_I2C lcd(TX_LCD_ADDR, TX_LCD_COLS, TX_LCD_ROWS);

 
// RUNTIME STATE
 

static TxState  currentState  = TxState::IDLE;
static uint16_t melodyIndex   = 0;   // Current position within melody[][]
static uint8_t  seqNum        = 0;   // Packet sequence number (0–255, wraps)
static uint8_t  retryCount    = 0;   // Consecutive retransmission counter (shown on display)
static uint32_t ackWaitStart  = 0;   // Timestamp (ms) when WAITING_ACK began

// Session nonce — generated once per button press by sendHelloPacket().
// Per-packet IV is derived as: packetNonce = sessionNonce, last byte ^= seqNum.
static uint8_t  s_sessionNonce[HELLO_NONCE_SIZE];

// ChaCha20-Poly1305 cipher instance (re-initialised per packet via clear()).
static ChaChaPoly s_cipher;

// Pending packet snapshot — allows retransmission without re-reading melody arrays.
static uint8_t  pendingNoteIndex    = 0;
static uint16_t pendingNoteDuration = 0;   // Full duration in milliseconds

// Timestamp (ms) when WAIT_BETWEEN_NOTES state began.
static uint32_t noteWaitStart = 0;

// Debounce state (millis-based) 
// INPUT_PULLUP wiring: idle = HIGH, pressed = LOW.
static bool     btnLastRawState = HIGH; // Raw digitalRead from the previous call
static bool     btnStableState  = HIGH; // Debounce-confirmed stable state
static uint32_t btnLastChangeMs = 0;    // Time of the last raw state change

 
// BUTTON HELPER — millis-based debounce
// Returns true exactly once per physical button press (falling-edge detection).
// Must be called every iteration of loop() to accumulate timing correctly.
 
bool readButtonPress() {
  // Cast to bool: LOW = 0 = false, HIGH = 1 = true (INPUT_PULLUP logic).
  const bool rawReading = (digitalRead(TX_BUTTON_PIN) != LOW);

  // Any change in the raw signal resets the stability timer.
  if (rawReading != btnLastRawState) {
    btnLastChangeMs = millis();
    btnLastRawState = rawReading;
  }

  // Promote the raw reading to the stable state only after DEBOUNCE_DELAY_MS
  // of continuous stability — this rejects contact-bounce glitches.
  if ((millis() - btnLastChangeMs) >= DEBOUNCE_DELAY_MS) {
    if (rawReading != btnStableState) {
      btnStableState = rawReading;
      // Falling edge on INPUT_PULLUP line = operator pressed the button.
      if (btnStableState == false) {
        return true;
      }
    }
  }

  return false;
}

 
// PACKET HELPERS

// sendHelloPacket — generate a fresh session nonce and broadcast it.
//
// Called ONCE per button press (from FSM IDLE state) BEFORE any DataPacket
// is sent.  Both nodes will use this nonce as the base for per-packet IV
// derivation:
//   packetNonce[i] = s_sessionNonce[i]
//   packetNonce[11] ^= seqNum          // last byte encodes packet counter
//
// The nonce comes from getSecureRandom32() (ChaCha20 CSPRNG seeded at power-on
// with 256-bit hardware entropy), so it is cryptographically unique per session.
void sendHelloPacket() {
  // Fill s_sessionNonce with 12 CSPRNG bytes (3 × 32-bit words).
  for (uint8_t i = 0; i < HELLO_NONCE_SIZE; i += 4u) {
    const uint32_t word = getSecureRandom32();
    s_sessionNonce[i + 0u] = static_cast<uint8_t>(word);
    s_sessionNonce[i + 1u] = static_cast<uint8_t>(word >>  8u);
    s_sessionNonce[i + 2u] = static_cast<uint8_t>(word >> 16u);
    s_sessionNonce[i + 3u] = static_cast<uint8_t>(word >> 24u);
  }

  HelloPacket hello;
  hello.packet_type = PACKET_TYPE_HELLO;
  memcpy(hello.nonce, s_sessionNonce, HELLO_NONCE_SIZE);
  Serial.write(reinterpret_cast<const uint8_t*>(&hello), sizeof(HelloPacket));
}

void sendPacket(uint8_t noteIndex, uint16_t noteDurationMs, uint8_t seqNumber) {
  // Step 1 — Encode duration: 1 unit = DURATION_UNIT_MS ms, max 255 units.
  const uint8_t encodedDuration = static_cast<uint8_t>(
      min(static_cast<uint16_t>(255u),
          static_cast<uint16_t>(noteDurationMs / DURATION_UNIT_MS))
  );

  // Step 2 — Derive per-packet IV.
  // Base: s_sessionNonce (12 bytes from HelloPacket).
  // Modification: XOR the last byte with seqNumber so each packet
  //   gets a unique (key, nonce) pair while remaining cheap to compute.
  //   seqNum 0–255 guarantees no IV reuse within a single session.
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[HELLO_NONCE_SIZE - 1u] ^= seqNumber;

  // Step 3 — Build the open header bytes that serve as AAD.
  // Both packet_type and seq_num are authenticated but NOT encrypted:
  //   • packet_type: tampering it from DATA→HELLO is detected.
  //   • seq_num: tampering with it causes IV desync → MAC fails.
  const uint8_t aad[2] = { PACKET_TYPE_DATA, seqNumber };

  // Step 4 — Build plain-text payload (2 bytes).
  const uint8_t plaintext[DATA_PAYLOAD_SIZE] = { noteIndex, encodedDuration };

  // Step 5 — Run ChaCha20-Poly1305.
  //   clear()         → resets cipher state (mandatory before reuse)
  //   setKey()        → installs MASTER_PSK (256-bit PSK, never transmitted)
  //   setIV()         → installs the per-packet 96-bit nonce
  //   addAuthData()   → feeds the 2 AAD bytes into the Poly1305 MAC
  //   encrypt()       → XORs plaintext with ChaCha20 keystream → ciphertext
  //   computeTag()    → finalises the Poly1305 authentication tag (16 bytes)
  DataPacket pkt;
  pkt.packet_type = PACKET_TYPE_DATA;
  pkt.seq_num     = seqNumber;

  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);
  s_cipher.setIV(packetNonce, HELLO_NONCE_SIZE);
  s_cipher.addAuthData(aad, sizeof(aad));
  s_cipher.encrypt(pkt.payload, plaintext, DATA_PAYLOAD_SIZE);
  s_cipher.computeTag(pkt.mac, AUTH_TAG_SIZE);

  // Step 6 — Transmit 20 bytes over UART.
  Serial.write(reinterpret_cast<const uint8_t*>(&pkt), sizeof(DataPacket));
}

// formAndSendPacket — high-level entry point used by the FSM SENDING state.
//
// Workflow:
//   1. Snapshot the plain-text payload as the retransmit buffer.
//   2. Delegate to sendPacket() which owns the full ChaChaPoly pipeline.
void formAndSendPacket(uint8_t note_idx, uint16_t duration_ms) {
  // Snapshot the plain-text payload so the FSM can retransmit on NACK
  // without re-reading the melody arrays.
  pendingNoteIndex    = note_idx;
  pendingNoteDuration = duration_ms;

  sendPacket(note_idx, duration_ms, seqNum);
}

 
// DISPLAY HELPER
// Updates the LCD only when explicitly called — never in a busy-loop.
// Row 0: FSM state label.
// Row 1: current sequence number + last checksum in hex.
 
void updateTxDisplay(TxState state, uint8_t seqNumber, uint8_t retries) {
  lcd.clear();

  // Row 0: packet number + retry counter
  // Example: "PKT:5  RTY:2" — gives operator live ARQ visibility.
  lcd.setCursor(0, 0);
  lcd.print("PKT:");
  lcd.print(seqNumber);
  lcd.print("  RTY:");
  lcd.print(retries);

  // Row 1: FSM state label
  lcd.setCursor(0, 1);
  switch (state) {
    case TxState::IDLE:               lcd.print("IDLE");      break;
    case TxState::SENDING:            lcd.print("SENDING");   break;
    case TxState::WAITING_ACK:        lcd.print("WAIT ACK");  break;
    case TxState::WAIT_BETWEEN_NOTES: lcd.print("WAIT NOTE"); break;
  }
}

// ENTROPY POOL  (TX variant — includes human-timing jitter from button press)

// Pulse counter incremented by the ring oscillator ISR on pin 2 (INT0).
// volatile prevents the compiler from caching the value in a register.
static volatile uint32_t s_ringOscPulses = 0;
static void onRingOscPulse() { ++s_ringOscPulses; }

// mixEntropy — one step of the cryptographic sponge.
// Rotates the pool left by 1 bit, then XOR-folds in new entropy bits.
// Left-rotation ensures every bit of the pool eventually influences all others.
static inline uint32_t mixEntropy(uint32_t pool, uint32_t bits) {
  return ((pool << 1u) | (pool >> 31u)) ^ bits;
}

// generateEntropyPool (TX) — fills outputSeed[32] with 256 bits of entropy.
// The 32-byte output is structured as 8 independent 32-bit words.
// Each word is produced by a fresh pass over ALL seven hardware sources,
// ensuring that even if one source is biased in a given iteration, the
// others compensate through the rotate-XOR mixing chain.
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

    // Source 6: Human-timing jitter (TX only) — micros() drifts between iterations.
    pool = mixEntropy(pool, micros());

    // Source 7: Arduino software PRNG (obfuscation layer).
    pool = mixEntropy(pool, static_cast<uint32_t>(random()));

    // Write the 32-bit word into the output seed as 4 bytes (little-endian).
    outputSeed[wordIndex * 4u + 0u] = static_cast<uint8_t>(pool);
    outputSeed[wordIndex * 4u + 1u] = static_cast<uint8_t>(pool >>  8u);
    outputSeed[wordIndex * 4u + 2u] = static_cast<uint8_t>(pool >> 16u);
    outputSeed[wordIndex * 4u + 3u] = static_cast<uint8_t>(pool >> 24u);
  }
}

 
// ARDUINO ENTRY POINTS
 

void tx_setup() {
  // UART: 9600 8N1 — matches protocol specification and SimulIDE oscilloscope.
  Serial.begin(BAUD_RATE);

  // Button: internal pull-up keeps the line HIGH until the button pulls it LOW.
  pinMode(TX_BUTTON_PIN, INPUT_PULLUP);

  // I2C LCD (Aip31068 compatible, address 0x27).
  lcd.init();
  // lcd.backlight();

  // Harvest 256-bit hardware entropy and seed the ChaCha20 CSPRNG.
  // ~16 ms total (8 ring-oscillator gate windows of 2 ms each) — one-time cost.
  // The seed is scrubbed from the stack immediately after handing it to the cipher.
  {
    uint8_t entropySeed[32];
    generateEntropyPool(entropySeed);
    initCSPRNG(entropySeed);
    memset(entropySeed, 0, sizeof(entropySeed));
  }

  currentState = TxState::IDLE;
  updateTxDisplay(currentState, seqNum, retryCount);
}

void tx_loop() {
  // readButtonPress() must run every iteration so the debounce timer
  // keeps accumulating even when the FSM is not in IDLE.
  const bool buttonPressed = readButtonPress();

  switch (currentState) {

    case TxState::IDLE:
      // Wait for the operator to press the start button before transmitting.
      if (buttonPressed) {
        melodyIndex = 0;
        seqNum      = 0;
        retryCount  = 0;  // Fresh start — reset the retry display counter.

        // Handshake: generate a new session nonce and broadcast it to RX.
        // RX will store this nonce and use it (combined with seqNum) to derive
        // the per-packet IV for every subsequent DataPacket this session.
        // sendHelloPacket() fills s_sessionNonce internally, then transmits it.
        sendHelloPacket();

        // ENTROPY TEST (remove after validation)
        // Harvest the nonce at the exact microsecond of the button press so
        // human-timing jitter is maximally folded into the pool (Source 6).
    //  uint8_t seedBuf[32];
    //  generateEntropyPool(seedBuf);
    //  // Display first 4 bytes (word 0) as hex for quick visual check.
    //  const uint32_t previewWord =
    //      (static_cast<uint32_t>(seedBuf[3]) << 24u) |
    //      (static_cast<uint32_t>(seedBuf[2]) << 16u) |
    //      (static_cast<uint32_t>(seedBuf[1]) <<  8u) |
    //       static_cast<uint32_t>(seedBuf[0]);
    //  lcd.clear();
    //  lcd.setCursor(0, 0);
    //  lcd.print("TX KEY:");
    //  lcd.setCursor(0, 1);
    //  lcd.print(previewWord, HEX);  // e.g. "A3F1C72B"
    //  delay(3000);                  // Hold result on screen for 3 s
        // END ENTROPY TEST

        currentState = TxState::SENDING;
        updateTxDisplay(currentState, seqNum, retryCount);
      }
      break;

    case TxState::SENDING:
      if (melodyIndex >= MELODY_LENGTH) {
        // All notes delivered — melody is complete.
        currentState = TxState::IDLE;
        updateTxDisplay(currentState, seqNum, retryCount);
        break;
      }
      // Build, encrypt, and transmit the current note.
      // seqNum is NOT yet incremented — it advances only on ACK so that
      // every retransmission of the same note reuses the same key.
      formAndSendPacket(
          static_cast<uint8_t>(pgm_read_word(&melody[melodyIndex][0])),
          pgm_read_word(&melody[melodyIndex][1])
      );
      ackWaitStart = millis(); // Open the ACK receive window (50 ms).
      currentState = TxState::WAITING_ACK;
      updateTxDisplay(currentState, seqNum, retryCount);
      break;

    case TxState::WAITING_ACK:
      if (Serial.available() > 0) {
        const uint8_t response = static_cast<uint8_t>(Serial.read());

        if (response == ACK_BYTE) {
          // ACK: packet intact → enter the inter-note pause before advancing.
          // melodyIndex is NOT incremented here — WAIT_BETWEEN_NOTES still
          // needs pgm_read_word(&melody[melodyIndex][1]) to determine how long to pause.
          retryCount    = 0;
          noteWaitStart = millis();
          currentState  = TxState::WAIT_BETWEEN_NOTES;
          updateTxDisplay(currentState, seqNum, retryCount);

        } else if (response == NACK_BYTE) {
          // NACK: RX detected corruption → retransmit the SAME packet.
          retryCount++;
          formAndSendPacket(pendingNoteIndex, pendingNoteDuration);
          ackWaitStart = millis();
          updateTxDisplay(currentState, seqNum, retryCount);
        }
        // Any other byte (noise on the feedback line) is silently ignored.

      } else if ((millis() - ackWaitStart) >= ACK_TIMEOUT_MS) {
        // Timeout: no response within 50 ms → channel or ACK was lost.
        // Retransmit the SAME packet with the SAME seqNum.
        retryCount++;
        formAndSendPacket(pendingNoteIndex, pendingNoteDuration);
        ackWaitStart = millis();
        updateTxDisplay(currentState, seqNum, retryCount);
      }
      break;

    case TxState::WAIT_BETWEEN_NOTES:
      // Hold for the duration of the just-acknowledged note/pause before
      // sending the next packet. This preserves melody timing exactly,
      // including long pauses that exceed a single uint8_t in milliseconds.
      if ((millis() - noteWaitStart) >= pgm_read_word(&melody[melodyIndex][1])) {
        melodyIndex++;
        seqNum++;   // Advance together with melodyIndex so keys stay in sync.
        retryCount   = 0;
        currentState = TxState::SENDING;
        updateTxDisplay(currentState, seqNum, retryCount);
      }
      break;
  }
}

// Arduino sketch entry points 
void setup() { tx_setup(); }
void loop()  { tx_loop();  }
