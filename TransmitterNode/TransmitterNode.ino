// TRANSMITTER (Node A) — "The Conductor"
// Flash this sketch onto the TX Arduino Nano.
//
// Responsibilities:
//   - Read the start button (with millis-based debounce on D2).
//   - Walk through the Super Mario melody array packet by packet.
//   - formAndSendPacket(): full crypto pipeline (key gen → encrypt → checksum → send).
//   - Stop-and-Wait ARQ: after every SEND wait up to ACK_TIMEOUT_MS (50 ms) for ACK.
//     ACK  → advance melody (melodyIndex++, seqNum++).
//     NACK or timeout → retransmit the SAME packet with the SAME seqNum.
 

#include "transmitter.h"
#include <LiquidCrystal_AIP31068_I2C.h>

 
// CONSTANTS
 

// Total number of notes in the stored melody.
static const uint8_t MELODY_LENGTH = 24;

 
// MELODY DATA  (Super Mario Bros. — main theme, first phrase)
//
// Indices reference the receiver's universal frequency dictionary:
//   C4=0  C#4=1  D4=2  D#4=3  E4=4  F4=5  F#4=6  G4=7
//   G#4=8 A4=9   A#4=10 B4=11 C5=12 C#5=13 D5=14 D#5=15
//
// Durations are stored in tens of milliseconds (15 → 150 ms, 25 → 250 ms).
 
static const uint8_t noteIndices[MELODY_LENGTH] = {
  //  E4   E4   E4   C4   E4   G4   G4
      4,   4,   4,   0,   4,   7,   7,
  //  C5   G4   E4   A4   B4  A#4   A4
     12,   7,   4,   9,  11,  10,   9,
  //  G4   E4   G4   A4   F4   G4   E4   C4   D4   B4
      7,   4,   7,   9,   5,   7,   4,   0,   2,  11
};

static const uint8_t noteDurations[MELODY_LENGTH] = {
  //  8th  8th  8th  8th  qtr  qtr  qtr
     15,  15,  15,  15,  25,  25,  25,
  //  qtr  qtr  qtr  qtr  qtr  qtr  qtr
     25,  25,  25,  25,  25,  25,  25,
  //  8th  8th  8th  8th  8th  8th  qtr  qtr  qtr  hlf
     15,  15,  15,  15,  15,  15,  25,  25,  25,  40
};

 
// HARDWARE OBJECTS
 

// I2C LCD: 16 columns × 2 rows, Aip31068-compatible controller.
static LiquidCrystal_AIP31068_I2C lcd(TX_LCD_ADDR, TX_LCD_COLS, TX_LCD_ROWS);

 
// RUNTIME STATE
 

static TxState  currentState  = TxState::IDLE;
static uint8_t  melodyIndex   = 0;   // Current position within noteIndices[]
static uint8_t  seqNum        = 0;   // Packet sequence number (0–255, wraps)
static uint8_t  retryCount    = 0;   // Consecutive retransmission counter (shown on display)
static uint8_t  lastChecksum  = 0;   // Checksum of the last sent packet (internal only)
static uint32_t ackWaitStart  = 0;   // Timestamp (ms) when WAITING_ACK began

// Pending packet snapshot — allows retransmission without re-reading melody arrays.
static uint8_t pendingNoteIndex    = 0;
static uint8_t pendingNoteDuration = 0;

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
 

uint8_t generateDynamicKey(uint8_t seqNumber) {
  // The key changes with every packet so two identically-pitched notes appear
  // as different ciphertext bytes in the channel — replay-attack mitigation.
  // K_dynamic = SECRET_KEY ^ seq_num
  return SECRET_KEY ^ seqNumber;
}

uint8_t calculateChecksum(const uint8_t packet[PACKET_SIZE]) {
  // Checksum is computed AFTER encryption so it covers the full ciphertext
  // frame, protecting it against bit-flip corruption in the noisy channel.
  // CHK = B0 ^ B1 ^ B2 ^ B3
  return packet[PACKET_IDX_START]
       ^ packet[PACKET_IDX_NOTE]
       ^ packet[PACKET_IDX_DURATION]
       ^ packet[PACKET_IDX_SEQ];
}

void sendPacket(uint8_t noteIndex, uint8_t noteDuration, uint8_t seqNumber) {
  uint8_t packet[PACKET_SIZE];
  const uint8_t key = generateDynamicKey(seqNumber);

  // Step 1 — Assemble the frame with encrypted payload bytes.
  // Both payload fields are XOR-encrypted: C = M ^ K_dynamic
  packet[PACKET_IDX_START]    = START_MARKER;
  packet[PACKET_IDX_NOTE]     = noteIndex    ^ key;
  packet[PACKET_IDX_DURATION] = noteDuration ^ key;
  packet[PACKET_IDX_SEQ]      = seqNumber;

  // Step 2 — Compute checksum over the already-encrypted bytes.
  packet[PACKET_IDX_CHECKSUM] = calculateChecksum(packet);
  lastChecksum = packet[PACKET_IDX_CHECKSUM];

  // Step 3 — Transmit all 5 bytes via hardware UART.
  Serial.write(packet, PACKET_SIZE);
}

// formAndSendPacket — high-level crypto pipeline entry point
//
// Workflow (matches the spec from 05_encryption_approach.instructions.md):
//   1. Store plain-text payload as the pending retransmit snapshot.
//   2. Generate K_dynamic = SECRET_KEY ^ seqNum  ← replay-attack mitigation.
//   3. Encrypt: C_note = note_idx ^ K_dynamic
//               C_dur  = duration_idx ^ K_dynamic
//   4. Assemble 5-byte packet: [0xAA | C_note | C_dur | seqNum | CHK].
//   5. Compute CHK = B0 ^ B1 ^ B2 ^ B3  (over ciphertext, not plaintext).
//   6. Transmit via Serial.write().
void formAndSendPacket(uint8_t note_idx, uint8_t duration_idx) {
  // Snapshot the plain-text payload so the FSM can retransmit on NACK
  // without re-reading the melody arrays.
  pendingNoteIndex    = note_idx;
  pendingNoteDuration = duration_idx;

  // Delegate to sendPacket which owns the full assemble+encrypt+send pipeline.
  sendPacket(note_idx, duration_idx, seqNum);
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
    case TxState::IDLE:        lcd.print("IDLE");     break;
    case TxState::SENDING:     lcd.print("SENDING");  break;
    case TxState::WAITING_ACK: lcd.print("WAIT ACK"); break;
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
      formAndSendPacket(noteIndices[melodyIndex], noteDurations[melodyIndex]);
      ackWaitStart = millis(); // Open the ACK receive window (50 ms).
      currentState = TxState::WAITING_ACK;
      updateTxDisplay(currentState, seqNum, retryCount);
      break;

    case TxState::WAITING_ACK:
      if (Serial.available() > 0) {
        const uint8_t response = static_cast<uint8_t>(Serial.read());

        if (response == ACK_BYTE) {
          // ACK: packet intact → advance to the next note and reset the retry counter.
          melodyIndex++;
          seqNum++;        // Increment AFTER ACK so every retransmit uses the same key.
          retryCount   = 0;
          currentState = TxState::SENDING;
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
  }
}

// Arduino sketch entry points 
void setup() { tx_setup(); }
void loop()  { tx_loop();  }
