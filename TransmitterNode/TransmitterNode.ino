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
static uint16_t seqNum        = 0;   // Packet sequence number (0–65535, wraps)
static uint8_t  retryCount    = 0;   // Consecutive retransmission counter (shown on display)
static uint32_t ackWaitStart  = 0;   // Timestamp (ms) when WAITING_ACK began

// Auto-reconnect timer — fires every RECONNECT_INTERVAL_MS in RECONNECTING state.
static uint32_t lastReconnectAttempt = 0;

// Session nonce — generated once per button press by sendHelloPacket().
// Per-packet IV is derived as: packetNonce = sessionNonce,
// last two bytes XOR'd with the 16-bit seqNum (big-endian split):
//   packetNonce[10] ^= (seqNum >> 8) & 0xFF
//   packetNonce[11] ^=  seqNum       & 0xFF
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

// drainRxFifo — discard all bytes currently waiting in the 64-byte hardware
// UART RX FIFO before transmitting any packet.
//
// Problem it solves: if the channel was noisy before the session started,
// RX may have sent many NACKs (garbage parsed as corrupted DATA frames).
// Those NACKs accumulate in TX's RX FIFO.  When TX sends HELLO and then
// immediately polls Serial.available(), it reads a stale NACK, interprets
// it as rejection of the HELLO it just sent, and enters a retry storm.
//
// Calling drainRxFifo() at the start of every send function ensures we
// only ever see responses to the packet we are about to transmit.
static inline void drainRxFifo() {
  while (Serial.available() > 0) {
    Serial.read();
  }
}

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
  hello.flags = FLAG_SYN;
  memcpy(hello.nonce, s_sessionNonce, HELLO_NONCE_SIZE);

  // Drain stale responses before transmitting; see drainRxFifo() comment.
  drainRxFifo();
  // Prefix every packet (both HELLO and DATA) with the sync preamble so the
  // RX parser always requires 0xAA 0x55 before accepting any frame type.
  // Without this, a noise-generated 0x01 byte could hijack the session nonce.
  Serial.write(SYNC_BYTE_1);
  Serial.write(SYNC_BYTE_2);
  Serial.write(reinterpret_cast<const uint8_t*>(&hello), sizeof(HelloPacket));
}

void sendPacket(uint8_t noteIndex, uint16_t noteDurationMs, uint16_t seqNumber) {
  // Step 1 — Derive per-packet IV using the full 16-bit sequence number.
  // Spreading seqNumber across bytes[10..11] of the 12-byte nonce ensures
  // all 65536 possible sequence numbers produce a distinct IV.
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[10] ^= static_cast<uint8_t>((seqNumber >> 8u) & 0xFFu);
  packetNonce[11] ^= static_cast<uint8_t>(seqNumber         & 0xFFu);

  // Step 2 — Populate packet header (used also as the 3-byte AAD).
  DataPacket pkt;
  pkt.flags   = FLAG_DAT;
  pkt.seq_num = seqNumber;

  // Step 3 — AAD is the 3 open header bytes: flags(1) + seq_num(2).
  // Any tampering with these fields causes MAC verification to fail.
  // We feed the raw struct bytes so the byte order matches what the receiver
  // will see on the wire (little-endian seq_num on AVR).
  const uint8_t aad[3] = {
    FLAG_DAT,
    static_cast<uint8_t>(seqNumber         & 0xFFu),  // seq_num low byte
    static_cast<uint8_t>((seqNumber >> 8u) & 0xFFu)   // seq_num high byte
  };

  // Step 4 — Build 4-byte plain-text payload.
  // payload[0] = note_index as uint16_t (values 0–20 or REST_INDEX=255)
  // payload[1] = duration in ms as uint16_t (direct, no DURATION_UNIT_MS encoding)
  const uint16_t plaintext[2] = {
    static_cast<uint16_t>(noteIndex),
    noteDurationMs
  };

  // Step 5 — Run ChaCha20-Poly1305.
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);
  s_cipher.setIV(packetNonce, HELLO_NONCE_SIZE);
  s_cipher.addAuthData(aad, sizeof(aad));
  s_cipher.encrypt(
    reinterpret_cast<uint8_t*>(pkt.payload),
    reinterpret_cast<const uint8_t*>(plaintext),
    DATA_PAYLOAD_SIZE  // 4 bytes
  );

  // Step 6 — Truncated MAC: compute full 16-byte Poly1305 tag, transmit only
  // the first TRUNCATED_MAC_SIZE (8) bytes.  This halves MAC overhead while
  // still providing 64-bit authentication strength — sufficient for a
  // noise-resilience demo over a short-range UART link.
  uint8_t full_mac[16];
  s_cipher.computeTag(full_mac, 16u);
  memcpy(pkt.mac, full_mac, TRUNCATED_MAC_SIZE);

  // Step 7 — Transmit: drain FIFO, then 2 sync bytes + 15-byte DataPacket = 17 bytes.
  // The sync preamble lets the receiver re-lock onto the frame boundary
  // after a noise burst without waiting for a new HelloPacket.
  drainRxFifo();
  Serial.write(SYNC_BYTE_1);
  Serial.write(SYNC_BYTE_2);
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
 
void updateTxDisplay(TxState state, uint16_t seqNumber, uint8_t retries) {
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
    case TxState::IDLE:               lcd.print("IDLE");         break;
    case TxState::RECONNECTING:       lcd.print("RECONNECTING"); break;
    case TxState::SENDING_HELLO:      lcd.print("SEND SYN");     break;
    case TxState::WAITING_HELLO_ACK:  lcd.print("WAIT SYN");     break;
    case TxState::SENDING:            lcd.print("SENDING");      break;
    case TxState::WAITING_ACK:        lcd.print("WAIT ACK");     break;
    case TxState::WAIT_BETWEEN_NOTES: lcd.print("WAIT NOTE");    break;
    case TxState::SENDING_FIN:        lcd.print("SEND FIN");     break;
    case TxState::WAITING_FIN_ACK:    lcd.print("WAIT FIN");     break;
  }
}

// sendFinPacket — transmit a FLAG_FIN session-teardown packet.
//
// Architecture mirrors sendPacket() exactly so that RX can authenticate
// the FIN using the same ChaChaPoly pipeline: same nonce derivation,
// same 3-byte AAD, same truncated (8-byte) Poly1305 MAC.
//
// Payload is encrypted zeros — no melody data is carried by the FIN frame.
// This prevents attackers from distinguishing a FIN from noise using the
// ciphertext alone; the flags byte in the AAD ties the MAC to FLAG_FIN.
void sendFinPacket() {
  // Step 1 — Derive per-packet nonce (identical derivation to sendPacket()).
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[10] ^= static_cast<uint8_t>((seqNum >> 8u) & 0xFFu);
  packetNonce[11] ^= static_cast<uint8_t>(seqNum         & 0xFFu);

  // Step 2 — Build packet header.
  DataPacket finPkt;
  finPkt.flags      = FLAG_FIN;
  finPkt.seq_num    = seqNum;
  finPkt.payload[0] = 0;
  finPkt.payload[1] = 0;

  // Step 3 — 3-byte AAD: FLAG_FIN(1) + seq_num(2).
  // Binding the flags byte to the MAC prevents any node from flipping
  // FLAG_DAT into FLAG_FIN mid-stream without MAC failure on the other side.
  const uint8_t aad[3] = {
    FLAG_FIN,
    static_cast<uint8_t>(seqNum         & 0xFFu),
    static_cast<uint8_t>((seqNum >> 8u) & 0xFFu)
  };

  // Step 4 — Encrypt zero payload so ciphertext is indistinguishable from data.
  const uint16_t plaintext[2] = {0u, 0u};
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);
  s_cipher.setIV(packetNonce, HELLO_NONCE_SIZE);
  s_cipher.addAuthData(aad, sizeof(aad));
  s_cipher.encrypt(
    reinterpret_cast<uint8_t*>(finPkt.payload),
    reinterpret_cast<const uint8_t*>(plaintext),
    DATA_PAYLOAD_SIZE
  );

  // Step 5 — Truncated MAC (8 bytes of 16-byte Poly1305 tag).
  uint8_t full_mac[16];
  s_cipher.computeTag(full_mac, 16u);
  memcpy(finPkt.mac, full_mac, TRUNCATED_MAC_SIZE);

  // Step 6 — Transmit: drain FIFO, then 2 sync bytes + 15-byte DataPacket = 17 bytes.
  drainRxFifo();
  Serial.write(SYNC_BYTE_1);
  Serial.write(SYNC_BYTE_2);
  Serial.write(reinterpret_cast<const uint8_t*>(&finPkt), sizeof(DataPacket));
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

// suspendSession — link-loss teardown with melody position preserved.
//
// Called when retryCount reaches MAX_RETRIES in any WAITING_* state.
// Unlike a clean FIN close, this is an unclean abort: the receiver vanished
// without sending FLAG_FIN.  We erase the session nonce (forward-secrecy)
// but deliberately keep melodyIndex so RECONNECTING can resume from the
// exact note where the link dropped rather than restarting the whole melody.
// The blocking delay(2000) holds the error message long enough to read AND
// pre-arms lastReconnectAttempt so the first auto-ping fires after a full
// RECONNECT_INTERVAL_MS, giving the receiver time to reboot.
void suspendSession() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("LINK LOST!");
  lcd.setCursor(0, 1);
  lcd.print("RECONNECTING...");

  // Erase key material — the old nonce is no longer safe to use.
  memset(s_sessionNonce, 0, HELLO_NONCE_SIZE);
  // melodyIndex intentionally NOT reset — resume from point of failure.
  seqNum       = 0;
  retryCount   = 0;
  currentState = TxState::RECONNECTING;

  // Pre-arm the timer so the first auto-ping waits a full interval.
  lastReconnectAttempt = millis();

  delay(2000);  // Hold error message so the operator can read it.
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
        currentState = TxState::SENDING_HELLO;
        updateTxDisplay(currentState, seqNum, retryCount);
      }
      break;

    case TxState::SENDING_HELLO:
      // Generate a fresh CSPRNG nonce and broadcast it inside a SYN frame.
      // drainRxFifo() runs inside sendHelloPacket(), so any NACK bytes that
      // accumulated during a pre-session noise burst are purged first.
      sendHelloPacket();
      ackWaitStart = millis(); // Open the ACK receive window.
      currentState = TxState::WAITING_HELLO_ACK;
      updateTxDisplay(currentState, seqNum, retryCount);
      break;

    case TxState::WAITING_HELLO_ACK:
      if (Serial.available() > 0) {
        const uint8_t response = static_cast<uint8_t>(Serial.read());

        if (response == ACK_BYTE) {
          // RX confirmed the nonce — session is live, start sending melody.
          retryCount   = 0;
          currentState = TxState::SENDING;
          updateTxDisplay(currentState, seqNum, retryCount);
        } else {
          // NACK or noise: RX rejected the SYN (parser desync or burst).
          // Brief cooldown before retransmitting a fresh HelloPacket so the
          // RX UART FIFO has time to drain, and a new nonce is generated to
          // keep the replay window always moving forward.
          retryCount++;
          if (retryCount >= MAX_RETRIES) {
            suspendSession();
          } else {
            delay(10);
            currentState = TxState::SENDING_HELLO;
            updateTxDisplay(currentState, seqNum, retryCount);
          }
        }

      } else if ((millis() - ackWaitStart) >= ACK_TIMEOUT_MS) {
        // Timeout: HELLO was lost or RX FIFO was overwhelmed — retransmit.
        retryCount++;
        if (retryCount >= MAX_RETRIES) {
          suspendSession();
        } else {
          currentState = TxState::SENDING_HELLO;
          updateTxDisplay(currentState, seqNum, retryCount);
        }
      }
      break;

    case TxState::SENDING:
      if (melodyIndex >= MELODY_LENGTH) {
        // All notes delivered — initiate session teardown instead of going idle.
        // This guard is a safety net; in normal flow WAIT_BETWEEN_NOTES detects
        // melody completion and transitions to SENDING_FIN directly.
        currentState = TxState::SENDING_FIN;
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
          // NACK: RX detected corruption → wait briefly then retransmit the SAME packet.
          // delay(10) gives the RX UART buffer time to drain residual noise bytes
          // before the retransmission arrives, reducing cascading NACK storms.
          retryCount++;
          if (retryCount >= MAX_RETRIES) {
            suspendSession();
          } else {
            delay(10);
            formAndSendPacket(pendingNoteIndex, pendingNoteDuration);
            ackWaitStart = millis();
            updateTxDisplay(currentState, seqNum, retryCount);
          }
        }
        // Any other byte (noise on the feedback line) is silently ignored.

      } else if ((millis() - ackWaitStart) >= ACK_TIMEOUT_MS) {
        // Timeout: no response within 50 ms → channel or ACK was lost.
        // Retransmit the SAME packet with the SAME seqNum.
        retryCount++;
        if (retryCount >= MAX_RETRIES) {
          suspendSession();
        } else {
          formAndSendPacket(pendingNoteIndex, pendingNoteDuration);
          ackWaitStart = millis();
          updateTxDisplay(currentState, seqNum, retryCount);
        }
      }
      break;

    case TxState::WAIT_BETWEEN_NOTES:
      // Hold for the duration of the just-acknowledged note/pause before
      // sending the next packet. This preserves melody timing exactly,
      // including long pauses that exceed a single uint8_t in milliseconds.
      if ((millis() - noteWaitStart) >= pgm_read_word(&melody[melodyIndex][1])) {
        melodyIndex++;
        seqNum++;   // Advance together with melodyIndex so keys stay in sync.
        retryCount = 0;
        // When the last note has been acknowledged, move to teardown rather
        // than back to SENDING — the melody is complete.
        if (melodyIndex >= MELODY_LENGTH) {
          currentState = TxState::SENDING_FIN;
        } else {
          currentState = TxState::SENDING;
        }
        updateTxDisplay(currentState, seqNum, retryCount);
      }
      break;

    case TxState::SENDING_FIN:
      // Transmit the FLAG_FIN teardown packet with the current seqNum.
      // The packet is fully authenticated (ChaChaPoly), so RX can verify
      // it is a genuine end-of-session signal and not injected noise.
      retryCount = 0;
      sendFinPacket();
      ackWaitStart = millis();
      currentState = TxState::WAITING_FIN_ACK;
      updateTxDisplay(currentState, seqNum, retryCount);
      break;

    case TxState::WAITING_FIN_ACK:
      if (Serial.available() > 0) {
        const uint8_t response = static_cast<uint8_t>(Serial.read());

        if (response == ACK_BYTE) {
          // RX confirmed the FIN — session closed successfully (clean close).
          // CRITICAL: erase the session nonce from RAM so it cannot be
          // recovered by subsequent code or a reset-based side-channel.
          memset(s_sessionNonce, 0, HELLO_NONCE_SIZE);
          melodyIndex  = 0;  // Clean close — restart melody from the beginning.
          seqNum       = 0;
          retryCount   = 0;
          currentState = TxState::IDLE;
          updateTxDisplay(currentState, seqNum, retryCount);

        } else if (response == NACK_BYTE) {
          // RX rejected the FIN (MAC failure) — retransmit after a brief drain.
          retryCount++;
          if (retryCount >= MAX_RETRIES) {
            suspendSession();
          } else {
            delay(10);
            currentState = TxState::SENDING_FIN;
            updateTxDisplay(currentState, seqNum, retryCount);
          }
        }
        // Any other byte — noise on the feedback line, stay in WAITING_FIN_ACK.

      } else if ((millis() - ackWaitStart) >= ACK_TIMEOUT_MS) {
        // Timeout: ACK lost in transit — retransmit the FIN packet.
        retryCount++;
        if (retryCount >= MAX_RETRIES) {
          suspendSession();
        } else {
          currentState = TxState::SENDING_FIN;
          updateTxDisplay(currentState, seqNum, retryCount);
        }
      }
      break;

    case TxState::RECONNECTING:
      // Auto-Resume state: entered after suspendSession() when the link drops
      // mid-melody. melodyIndex is preserved so we resume from where we left off.
      //
      // Button press  = operator forces a hard restart from note 0.
      // Auto-timer    = silent HELLO ping every RECONNECT_INTERVAL_MS.
      if (buttonPressed) {
        // Manual override: discard progress, restart melody from the beginning.
        melodyIndex  = 0;
        seqNum       = 0;
        retryCount   = 0;
        currentState = TxState::SENDING_HELLO;
        updateTxDisplay(currentState, seqNum, retryCount);
        break;
      }
      if ((millis() - lastReconnectAttempt) >= RECONNECT_INTERVAL_MS) {
        // Auto-ping: attempt a new HELLO handshake to resume the session.
        // On success WAITING_HELLO_ACK → SENDING will pick up at melodyIndex.
        // On MAX_RETRIES suspendSession() re-enters RECONNECTING (keeps trying).
        lastReconnectAttempt = millis();
        currentState = TxState::SENDING_HELLO;
        updateTxDisplay(currentState, seqNum, retryCount);
      }
      break;
  }
}

// Arduino sketch entry points 
void setup() { tx_setup(); }
void loop()  { tx_loop();  }
