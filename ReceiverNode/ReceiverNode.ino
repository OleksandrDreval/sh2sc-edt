/**
 * @file ReceiverNode.ino
 * @brief SH2SC-EDT — Receiver Node B ("The Synthesizer") firmware.
 * @details Implements the C2P-ARQ protocol receive side. Responsibilities:
 *          - Initialise UART at 9600 bps, I2C LCD (Aip31068), and piezo buzzer.
 *          - Hold the universal note-frequency dictionary (indices 0–20, C4–G#5).
 *          - Byte-level frame parser FSM: WAIT_AA -> WAIT_55 -> READ_TYPE -> READ_PAYLOAD.
 *          - processHelloBody(): accept session nonce from HelloPacket, install PSK.
 *          - authenticateAndPlay(): full ChaCha20-Poly1305 pipeline; note is played
 *            only after memcmp(expectedMac, pkt->mac, TRUNCATED_MAC_SIZE) == 0.
 *          - processFinPacket(): authenticated session teardown with key erasure.
 *          - Dynamic Smart Watchdog: auto-teardown if TX disappears without FLAG_FIN.
 *          - Non-blocking buzzer timing via millis().
 * @note    Part of the SH2SC-EDT project. Flash onto the RX Arduino Nano (Node B).
 */

#include "receiver.h"
#include <LiquidCrystal_AIP31068_I2C.h>

/**
 * @brief Universal note frequency dictionary for the C2P-ARQ Receiver.
 * @details Maps an encoded note index (0–20) sent by Transmitter Node A to the
 *          corresponding buzzer frequency in Hz. The RX node has no knowledge of
 *          which melody is playing — it only translates index -> frequency.
 *          Index layout (chromatic scale, C4 … G#5):
 *          @code
 *            0=C4  1=C#4  2=D4  3=D#4  4=E4   5=F4   6=F#4  7=G4
 *            8=G#4 9=A4  10=A#4 11=B4  12=C5  13=C#5 14=D5  15=D#5
 *           16=E5  17=F5  18=F#5 19=G5  20=G#5
 *          @endcode
 *          REST_INDEX (255) means silence — handled separately in authenticateAndPlay().
 */
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

/// @brief I2C LCD display object (Aip31068, 16×2, address 0x3E).
static LiquidCrystal_AIP31068_I2C lcd(RX_LCD_ADDR, RX_LCD_COLS, RX_LCD_ROWS);

/**
 * @brief Four-state byte-level frame assembly FSM states.
 * @details Drives processReceivedByte(). Both HELLO and DATA frames must pass
 *          through the 0xAA 0x55 preamble gate before any body bytes are accepted.
 */
enum ParseState : uint8_t { WAIT_AA, WAIT_55, READ_TYPE, READ_PAYLOAD };
/// @brief Current byte-parser FSM state; reset to WAIT_AA by resetParser().
static ParseState parseState = WAIT_AA;

/**
 * @brief Raw receive buffer sized to hold the largest frame body (DataPacket, 15 bytes).
 * @details HelloPacket (13 bytes) also fits. @c rx_buffer[0] always holds the @c flags
 *          byte; casting to the appropriate struct pointer gives zero-copy struct access.
 */
static uint8_t rx_buffer[sizeof(DataPacket)];
/// @brief Number of bytes written to rx_buffer for the frame currently being collected.
static uint8_t rx_index       = 0;
/// @brief Total expected bytes for the current frame; set in READ_TYPE state.
static uint8_t expected_length = 0;

/// @brief Session active flag — set after a valid HelloPacket handshake; cleared on FIN or watchdog timeout.
static bool     s_sessionActive = false;
/// @brief 12-byte session nonce delivered by the last accepted HelloPacket (FLAG_SYN).
static uint8_t  s_sessionNonce[HELLO_NONCE_SIZE];

/// @brief ChaCha20-Poly1305 cipher instance; re-initialised per packet via clear().
static ChaChaPoly s_cipher;

/// @brief Timestamp (millis()) when the current note started playing.
static uint32_t noteStartMs  = 0;
/// @brief Duration in milliseconds that the current note should sound.
static uint16_t noteLengthMs = 0;
/// @brief True while a note is actively sounding; cleared by stopNote().
static bool     isPlayingNote = false;

/// @brief Duration of the MAC-error message shown on the LCD before returning to idle display.
const uint16_t  CHK_ERR_DISPLAY_MS = 500;
/// @brief True when the LCD is currently showing a MAC-error message.
static bool     isShowingError      = false;
/// @brief Timestamp (millis()) when the MAC-error display was last activated.
static uint32_t errorDisplayStart   = 0;

/**
 * @brief Stale byte accumulation timeout for the byte-level frame parser.
 * @details If body bytes stop arriving mid-frame for longer than this value,
 *          resetParser() is called to prevent a permanently stalled accumulator.
 */
const uint16_t  RX_PARSER_TIMEOUT_MS = 20;
/// @brief Timestamp (millis()) of the most recently received UART byte.
static uint32_t rxLastByteMs         = 0;

/**
 * @brief Network grace period added to the last note's duration for the Dynamic Smart Watchdog.
 * @details Absorbs the worst-case TX retry storm: MAX_RETRIES × ACK_TIMEOUT_MS = 50 × 50 ms = 2500 ms.
 *          Value 3000 ms provides 500 ms margin above that maximum.
 */
const uint32_t  NETWORK_GRACE_PERIOD_MS = 3000;
/**
 * @brief Current Dynamic Watchdog timeout in milliseconds.
 * @details Updated after every authenticated DataPacket to
 *          (last note duration + NETWORK_GRACE_PERIOD_MS). Default 5000 ms until
 *          the first DATA packet establishes a note duration.
 */
static uint32_t current_timeout_limit  = 5000;
/// @brief Timestamp (millis()) of the most recently successfully authenticated DataPacket.
static uint32_t last_valid_packet_time = 0;

/// @brief Tracks the current RxState for LCD display updates; independent of the byte-parser FSM.
static RxState currentState = RxState::WAITING_SYNC_1;

/**
 * @brief Refresh the RX LCD with the current FSM state and last packet result.
 * @details Row 0 shows a human-readable RxState label; Row 1 shows
 *          @c SEQ:<seqNum> OK or @c SEQ:<seqNum> MAC! depending on @p macOk.
 * @param state  Current @c RxState to display on LCD row 0.
 * @param seqNum Last received sequence number for LCD row 1.
 * @param macOk  @c true if MAC verification passed; @c false on failure.
 */
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

/**
 * @brief Flush the UART RX FIFO and reset the byte-parser FSM to WAIT_AA.
 * @details Called on MAC failure or parser timeout to prevent a noise burst that
 *          corrupted one frame from also corrupting the preamble detection of the
 *          next frame. Reads and discards all bytes in the 64-byte hardware FIFO
 *          (Serial.flush() only flushes TX; manual drain is required for RX).
 */
static void resetParser() {
  // Drain any garbage in the 64-byte hardware UART RX FIFO.
  while (Serial.available() > 0) {
    Serial.read();
  }
  rx_index     = 0;
  parseState   = WAIT_AA;
  currentState = RxState::WAITING_SYNC_1;
}

/**
 * @brief Consume one incoming UART byte and advance the frame-assembly FSM.
 * @details Implements the WAIT_AA -> WAIT_55 -> READ_TYPE -> READ_PAYLOAD pipeline.
 *          Both HELLO and DATA frames must pass the 0xAA 0x55 preamble gate.
 *          On buffer completion, dispatches to processHelloBody(), authenticateAndPlay(),
 *          or processFinPacket() as appropriate, then returns to WAIT_AA.
 * @param inByte Byte just read from the UART hardware buffer.
 */
void processReceivedByte(uint8_t inByte) {
  switch (parseState) {

    // Preamble scan: ALL packet types (HELLO and DATA) are prefixed with 0xAA 0x55.
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

    // Packet-type discriminator: preamble confirmed.
    // Bitwise-AND (not ==) for flag matching: tolerates noise-resilient multi-flag frames.

    case READ_TYPE:
      rx_buffer[0] = inByte;
      rx_index     = 1;
      if (inByte & FLAG_SYN) {
        // SYN frame — HelloPacket (13 bytes): flags(1) + nonce(12).
        expected_length = static_cast<uint8_t>(sizeof(HelloPacket));
        parseState      = READ_PAYLOAD;
        currentState    = RxState::READING_HELLO;
        updateRxDisplay(currentState, 0, false);
      } else if (inByte & FLAG_DAT) {
        // DAT frame — DataPacket (15 bytes): flags(1) + seq_num(2) + payload(4) + mac(8).
        expected_length = static_cast<uint8_t>(sizeof(DataPacket));
        parseState      = READ_PAYLOAD;
        currentState    = RxState::READING_DATA;
      } else if (inByte & FLAG_FIN) {
        // FIN frame — DataPacket-sized session-teardown frame.
        expected_length = static_cast<uint8_t>(sizeof(DataPacket));
        parseState      = READ_PAYLOAD;
        currentState    = RxState::READING_DATA;
      } else {
        // No recognised flag bit — channel noise, restart preamble scan.
        rx_index   = 0;
        parseState = WAIT_AA;
      }
      break;

    // Body collection: accumulate bytes until the full frame is in rx_buffer, then dispatch.
    // rx_buffer[0] = flags byte, rx_buffer[1..] = remaining struct fields.

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

/**
 * @brief Store the received session nonce and install MASTER_PSK into the cipher.
 * @details Copies @c rx_buffer[1..12] into @c s_sessionNonce, calls
 *          @c s_cipher.setKey(MASTER_PSK, 32) to pre-install the key, sets
 *          @c s_sessionActive = true, sends @c ACK_BYTE, and arms the Dynamic
 *          Smart Watchdog with @c current_timeout_limit = 5000 ms.
 */
void processHelloBody() {
  // rx_buffer[0]     = flags byte (FLAG_SYN confirmed).
  // rx_buffer[1..12] = 12-byte CSPRNG nonce from TX sendHelloPacket().
  memcpy(s_sessionNonce, &rx_buffer[1], HELLO_NONCE_SIZE);

  // Pre-install the key so that per-packet handling only needs setIV().
  s_cipher.clear();
  s_cipher.setKey(MASTER_PSK, 32u);

  s_sessionActive = true;

  // Confirm to TX that the nonce was received and the session key is armed.
  // Without this ACK, TX's WAITING_HELLO_ACK state would time out and keep
  // retransmitting a new HelloPacket on every cycle.
  Serial.write(ACK_BYTE);

  // Arm the session watchdog: start the silence timer from this moment.
  // Timeout is capped at 5 s until the first DATA packet reveals note duration.
  current_timeout_limit  = 5000;
  last_valid_packet_time = millis();
}

/**
 * @brief Run the full ChaCha20-Poly1305 pipeline; play the note only on MAC success.
 * @details Pipeline (mirrors TX sendPacket()):
 *          1. Read @c seq_num from the packed struct field directly.
 *          2. Derive per-packet nonce: local copy of @c s_sessionNonce, then
 *             @c packetNonce[10] ^= (seqNum >> 8), @c packetNonce[11] ^= seqNum.
 *          3. @c clear() -> @c setKey(MASTER_PSK, 32) -> @c setIV(packetNonce, 12).
 *          4. @c addAuthData({flags, seq_lo, seq_hi}, 3) — 3-byte plaintext AAD.
 *          5. @c decrypt(pkt->payload, plaintext, DATA_PAYLOAD_SIZE).
 *          6. @c computeTag(expectedMac, 16), then memcmp with truncated 8-byte tag.
 *          Security invariant: startNote() is called ONLY after memcmp returns 0.
 *          Also bounds-checks @c noteIndex < NOTE_DICT_SIZE before indexing
 *          @c universal_notes[] to prevent out-of-bounds reads on ATmega328P.
 * @param pkt Pointer to the fully buffered DataPacket (flags == FLAG_DAT).
 */
void authenticateAndPlay(const DataPacket* pkt) {
  const uint16_t seqNum = pkt->seq_num;

  // Step 1 — Derive per-packet nonce from a local copy of s_sessionNonce.
  // NEVER XOR directly into s_sessionNonce — would corrupt every subsequent IV.
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[10] ^= static_cast<uint8_t>((seqNum >> 8u) & 0xFFu);
  packetNonce[11] ^= static_cast<uint8_t>(seqNum         & 0xFFu);

  // Step 2 — 3-byte AAD: flags + both bytes of seq_num (must match TX byte-for-byte).
  // Any tamper to the flags byte or sequence number will fail the MAC.
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

  // Step 4 — Decrypt 4-byte payload; decrypt() simultaneously advances Poly1305 state.
  uint16_t plaintext[2];  // [0]=note_index, [1]=duration_ms
  s_cipher.decrypt(
    reinterpret_cast<uint8_t*>(plaintext),
    reinterpret_cast<const uint8_t*>(pkt->payload),
    DATA_PAYLOAD_SIZE
  );

  // Step 5 — Verify truncated 8-byte Poly1305 MAC.
  // computeTag()+memcmp() is used because the library's checkTag() requires the full 16-byte tag.
  uint8_t expectedMac[16];
  s_cipher.computeTag(expectedMac, 16u);

  if (memcmp(expectedMac, pkt->mac, TRUNCATED_MAC_SIZE) != 0) {
    // MAC mismatch: noise corruption or forgery — NEVER play a note on failed MAC.
    // Flush UART FIFO via resetParser(); the same burst likely left more garbage.
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

  // Step 7 — Extract decoded fields; duration is in direct milliseconds (no scaling).
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

  // Dynamic watchdog: extend timeout by note duration + grace period.
  // Prevents a long note or post-note silence from triggering a false session reset.
  current_timeout_limit  = static_cast<uint32_t>(durationMs) + NETWORK_GRACE_PERIOD_MS;
  last_valid_packet_time = millis();
}

/**
 * @brief Authenticate and process a FLAG_FIN session-teardown packet.
 * @details Cryptographic pipeline is identical to authenticateAndPlay() to guarantee
 *          that only the legitimate TX (holding MASTER_PSK and s_sessionNonce) can
 *          produce a verifiable FIN. A noise-induced FLAG_FIN byte will fail MAC and
 *          trigger NACK without touching the session state.
 *          Uses @c discardBuf to receive the zero plaintext — @c decrypt() MUST run
 *          before @c computeTag() to correctly advance the Poly1305 accumulator.
 *          On MAC success: ACK sent, @c s_sessionNonce zeroed (key erasure), parser reset.
 *          On MAC failure: NACK sent, session left active for FIN retransmission.
 * @param pkt Pointer to the fully buffered DataPacket (flags == FLAG_FIN).
 */
void processFinPacket(const DataPacket* pkt) {
  const uint16_t seqNum = pkt->seq_num;

  // Step 1 — Derive per-packet nonce (same derivation as TX sendFinPacket()).
  uint8_t packetNonce[HELLO_NONCE_SIZE];
  memcpy(packetNonce, s_sessionNonce, HELLO_NONCE_SIZE);
  packetNonce[10] ^= static_cast<uint8_t>((seqNum >> 8u) & 0xFFu);
  packetNonce[11] ^= static_cast<uint8_t>(seqNum         & 0xFFu);

  // Step 2 — 3-byte AAD: FLAG_FIN + seq_num bytes (must match TX sendFinPacket() exactly).
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
  // TX encrypts zeros; decrypt() MUST run before computeTag() to advance Poly1305 state.
  // Skipping decrypt() produces an incorrect expected MAC and causes false NACK on valid FIN.
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
    // Session remains active so TX can retransmit the FIN.
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

  // Step 8 — CRITICAL: erase the session nonce from RAM (forward secrecy).
  // With the nonce gone, no future replay of captured ciphertext can be decrypted.
  memset(s_sessionNonce, 0, HELLO_NONCE_SIZE);
  s_sessionActive = false;

  // Step 9 — Return parser to clean idle state, ready for the next SYN.
  resetParser();
}

/**
 * @brief Start non-blocking note playback on the piezo buzzer.
 * @details Calls tone(RX_BUZZER_PIN, frequencyHz), records noteStartMs = millis(),
 *          and sets isPlayingNote = true. rx_loop() will call stopNote() when
 *          (millis() - noteStartMs) >= noteLengthMs. For frequencyHz == 0 (REST),
 *          no tone is started and isPlayingNote is still set to handle timing.
 * @param frequencyHz Frequency in Hz to pass to tone(); 0 = silence.
 * @param durationMs  Duration in milliseconds to hold the note before calling noTone().
 */
void startNote(uint16_t frequencyHz, uint16_t durationMs) {
  tone(RX_BUZZER_PIN, frequencyHz);
  noteStartMs   = millis();
  noteLengthMs  = durationMs;
  isPlayingNote = true;
}

/**
 * @brief Stop the currently playing note and clear the playback flag.
 * @details Calls noTone(RX_BUZZER_PIN) and sets isPlayingNote = false.
 *          Called by rx_loop() when (millis() - noteStartMs) >= noteLengthMs.
 */
void stopNote() {
  noTone(RX_BUZZER_PIN);
  isPlayingNote = false;
}

/// @brief Pulse counter incremented by the ring oscillator ISR on INT0 (pin 2).
static volatile uint32_t s_ringOscPulses = 0;
/// @brief Ring oscillator ISR — increments pulse counter on each RISING edge.
static void onRingOscPulse() { ++s_ringOscPulses; }

/**
 * @brief Single-step cryptographic entropy mixer — rotate-left XOR fold.
 * @details Rotates @p pool left by 1 bit, then XORs in @p bits.
 *          Used iteratively by generateEntropyPool() for each entropy source.
 * @param pool Accumulated entropy pool value.
 * @param bits New entropy bits to fold in.
 * @return Mixed pool value.
 */
static inline uint32_t mixEntropy(uint32_t pool, uint32_t bits) {
  return ((pool << 1u) | (pool >> 31u)) ^ bits;
}

/**
 * @brief Harvest 256 bits of hardware entropy and fill @p outputSeed (RX variant).
 * @details Fills @c outputSeed[32] as 8 independent 32-bit words, each gathered
 *          from six hardware sources (micros() human-timing jitter is omitted — RX
 *          has no button):
 *          1. Ring oscillator on INT0 (pin 2): pulse count over a 2 ms gate.
 *          2. Uninitialised SRAM bytes at 0x0100 + wordIndex*8 (8 bytes per word).
 *          3. On-die temperature ADC (channel 8, 1.1 V reference): 8 LSBs per word.
 *          4. TCNT1 free-running timer snapshot (2 bytes).
 *          5. A0 white-noise ADC: 8 LSBs per word.
 *          6. Arduino software PRNG random() (obfuscation layer).
 *
 *          Total execution time: 8 × 2 ms gate ≈ 16 ms (one-shot in rx_setup()).
 * @param outputSeed Pointer to a 32-byte buffer for the entropy pool output.
 *                   Pass directly to initCSPRNG(); scrub with memset() afterwards.
 * @note Invoke once during rx_setup(), before the UART receive loop starts.
 */
void generateEntropyPool(uint8_t* outputSeed) {
  // SRAM base: 64 uninitialised bytes starting at 0x0100 on ATmega328P.
  // Each word draws from a distinct non-overlapping 8-byte slice.
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

    // NOTE: micros() human-timing jitter is intentionally absent on RX — no button present.

    // Source 6: Arduino software PRNG (obfuscation layer).
    pool = mixEntropy(pool, static_cast<uint32_t>(random()));

    // Write the 32-bit word into the output seed as 4 bytes (little-endian).
    outputSeed[wordIndex * 4u + 0u] = static_cast<uint8_t>(pool);
    outputSeed[wordIndex * 4u + 1u] = static_cast<uint8_t>(pool >>  8u);
    outputSeed[wordIndex * 4u + 2u] = static_cast<uint8_t>(pool >> 16u);
    outputSeed[wordIndex * 4u + 3u] = static_cast<uint8_t>(pool >> 24u);
  }
}

/**
 * @brief Initialise RX hardware, seed the CSPRNG, and display the idle screen.
 * @details Configures UART @ 9600 bps, buzzer pin, I2C LCD, and byte-parser FSM.
 *          Harvests 256-bit hardware entropy (~16 ms) and seeds the ChaCha20 CSPRNG.
 *          The entropy buffer is scrubbed from the stack immediately after use.
 */
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

/**
 * @brief Execute one non-blocking C2P-ARQ FSM tick for the Receiver node.
 * @details Handles the MAC-error display timer, note-duration timer, Dynamic
 *          Smart Watchdog tear-down, non-blocking UART byte reading, and parser
 *          timeout. At most one FSM transition per invocation; no delay() calls.
 */
void rx_loop() {
  // MAC error-flash expiry: restore normal display after CHK_ERR_DISPLAY_MS.
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

  // SESSION WATCHDOG — prevents deadlock if TX disappears without sending FLAG_FIN.
  // current_timeout_limit is updated dynamically: 5 s initially, then
  // (last note duration + NETWORK_GRACE_PERIOD_MS) after each authenticated packet.
  if (s_sessionActive &&
      (millis() - last_valid_packet_time) > current_timeout_limit) {
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("TIMEOUT! DROP");
    lcd.setCursor(0, 1);
    lcd.print("Session reset");
    // Erase key material so replayed captured ciphertext cannot be decrypted.
    memset(s_sessionNonce, 0, HELLO_NONCE_SIZE);
    s_sessionActive = false;
    resetParser();
  }

  // Non-blocking UART reading; processReceivedByte() handles all parsing and crypto.
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    rxLastByteMs = millis();
    processReceivedByte(inByte);
  }

  // PARSER TIMEOUT — self-healing against mid-packet desync caused by a noise burst.
  if (rx_index > 0 && parseState != WAIT_AA &&
      (millis() - rxLastByteMs) >= RX_PARSER_TIMEOUT_MS) {
    resetParser();
    updateRxDisplay(RxState::WAITING_SYNC_1, 0, false);
  }
}

/// @brief Arduino entry point — delegates to rx_setup().
void setup() { rx_setup(); }
/// @brief Arduino main loop — delegates to rx_loop().
void loop()  { rx_loop();  }
