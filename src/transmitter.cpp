 
// TRANSMITTER (Node A) — "The Conductor"
// Flash this sketch onto the TX Arduino Nano.
//
// Responsibilities:
//   - Read the start button (with millis-based debounce on D2).
//   - Walk through the Super Mario melody array packet by packet.
//   - FSM: IDLE → SENDING → WAITING_ACK (→ IDLE when melody ends).
//   - Sending and ACK logic are intentionally left as TODO stubs.
 

#include "../include/transmitter.h"
#include <LiquidCrystal_I2C.h>

 
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
 

// I2C LCD: 16 columns × 2 rows, Aip31068-compatible via LiquidCrystal_I2C.
static LiquidCrystal_I2C lcd(TX_LCD_ADDR, TX_LCD_COLS, TX_LCD_ROWS);

 
// RUNTIME STATE
 

static TxState  currentState  = TxState::IDLE;
static uint8_t  melodyIndex   = 0;   // Current position within noteIndices[]
static uint8_t  seqNum        = 0;   // Packet sequence number (0–255, wraps)
static uint8_t  lastChecksum  = 0;   // Checksum of the last sent packet (display only)
static uint32_t ackWaitStart  = 0;   // Timestamp (ms) when WAITING_ACK began

// Pending packet payload — stored so the packet can be retransmitted on NACK.
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

 
// DISPLAY HELPER
// Updates the LCD only when explicitly called — never in a busy-loop.
// Row 0: FSM state label.
// Row 1: current sequence number + last checksum in hex.
 
void updateTxDisplay(TxState state, uint8_t seqNumber, uint8_t checksum) {
  lcd.clear();

  lcd.setCursor(0, 0);
  switch (state) {
    case TxState::IDLE:        lcd.print("IDLE");     break;
    case TxState::SENDING:     lcd.print("SENDING");  break;
    case TxState::WAITING_ACK: lcd.print("WAIT ACK"); break;
  }

  lcd.setCursor(0, 1);
  lcd.print("SEQ:");
  lcd.print(seqNumber);
  lcd.print(" CHK:0x");
  if (checksum < 0x10) lcd.print('0'); // Zero-pad single hex digit
  lcd.print(checksum, HEX);
}

 
// ARDUINO ENTRY POINTS
 

void tx_setup() {
  // UART: 9600 8N1 — matches protocol specification and SimulIDE oscilloscope.
  Serial.begin(BAUD_RATE);

  // Button: internal pull-up keeps the line HIGH until the button pulls it LOW.
  pinMode(TX_BUTTON_PIN, INPUT_PULLUP);

  // I2C LCD (Aip31068 compatible, address 0x27).
  lcd.init();
  lcd.backlight();

  currentState = TxState::IDLE;
  updateTxDisplay(currentState, seqNum, 0);
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
        currentState = TxState::SENDING;
        updateTxDisplay(currentState, seqNum, lastChecksum);
      }
      break;

    case TxState::SENDING:
      // TODO (Stage 4): Read noteIndices[melodyIndex] and noteDurations[melodyIndex],
      //                 populate pendingNoteIndex / pendingNoteDuration,
      //                 call sendPacket(), set ackWaitStart = millis(),
      //                 then transition to WAITING_ACK.
      //
      // Stub — return to IDLE so the FSM does not get stuck during skeleton testing.
      currentState = TxState::IDLE;
      updateTxDisplay(currentState, seqNum, lastChecksum);
      break;

    case TxState::WAITING_ACK:
      // TODO (Stage 4): Listen on Serial for ACK_BYTE / NACK_BYTE.
      //   ACK  → melodyIndex++; seqNum++; → SENDING
      //   NACK → retransmit the pending packet; reset ackWaitStart; stay here.
      //   Timeout (millis() - ackWaitStart >= ACK_TIMEOUT_MS)
      //        → treat as NACK (retransmit or skip after MAX_RETRIES).
      break;
  }
}

// Arduino sketch entry points 
void setup() { tx_setup(); }
void loop()  { tx_loop();  }
