 
// RECEIVER (Node B) — "The Synthesizer"
// Flash this sketch onto the RX Arduino Nano.
 

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

// STUB HELPERS  (to be implemented in Stage 3)

bool validateChecksum(const uint8_t packet[PACKET_SIZE]) {
  // TODO (Stage 3): compute CHK_expected = B0^B1^B2^B3, compare with packet[4].
  (void)packet;
  return false;
}

void decryptAndPlay(const uint8_t packet[PACKET_SIZE]) {
  // TODO (Stage 3): K_dynamic = SECRET_KEY ^ packet[PACKET_IDX_SEQ],
  //                 decrypt noteIndex and durationTens, look up universal_notes[],
  //                 call startNote().
  (void)packet;
}

void startNote(uint16_t frequencyHz, uint16_t durationMs) {
  // TODO (Stage 3): tone(RX_BUZZER_PIN, frequencyHz), record millis().
  (void)frequencyHz;
  (void)durationMs;
}

void stopNote() {
  // TODO (Stage 3): noTone(RX_BUZZER_PIN).
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
  // Non-blocking UART reading
  // Read as many bytes as are waiting in the hardware UART buffer right now.
  // Nothing blocks here; if there are no bytes, the while-body never executes.
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    processReceivedByte(inByte);
  }

  // Resolve GOT_PACKET
  // The FSM lands here once all 5 bytes are buffered. Show a confirmation
  // message on the LCD, then reset and wait for the next packet.
  // Full validation and decryption will replace this block in Stage 3.
  if (currentState == RxState::GOT_PACKET) {
    updateRxDisplay(currentState, rx_buffer[PACKET_IDX_SEQ], false);

    // TODO (Stage 3): validateChecksum(); send ACK or NACK; decryptAndPlay().

    // Reset the buffer so the FSM is ready for the next incoming packet.
    bytesReceived = 0;
    currentState  = RxState::WAITING_FOR_START;
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
