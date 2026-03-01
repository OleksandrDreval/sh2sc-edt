 
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

void updateRxDisplay(RxState state, uint8_t seqNumber, bool checksumOk) {
  lcd.clear();

  // Row 0: FSM state label
  lcd.setCursor(0, 0);
  switch (state) {
    case RxState::WAITING_FOR_START:   lcd.print("WAIT START");  break;
    case RxState::READING_PAYLOAD:     lcd.print("READING...");  break;
    case RxState::VALIDATING_CHECKSUM: lcd.print("VALIDATING");  break;
    case RxState::EXECUTING_ACTION:    lcd.print("PLAYING");     break;
  }

  // Row 1: last sequence number and checksum result
  lcd.setCursor(0, 1);
  lcd.print("SEQ:");
  lcd.print(seqNumber);
  lcd.print(checksumOk ? " OK" : " ERR");
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
  // Once a note has been playing for its designated duration, silence the buzzer.
  if (isPlayingNote && ((millis() - noteStartMs) >= noteLengthMs)) {
    stopNote();
  }

  // Byte-by-byte FSM processing 
  while (Serial.available() > 0) {
    const uint8_t inByte = static_cast<uint8_t>(Serial.read());
    processReceivedByte(inByte);
  }

  // Resolve completed packet states 
  // These transitions are handled here (not inside processReceivedByte) so
  // we can send a serial response without re-entering the byte-processing path.
  if (currentState == RxState::VALIDATING_CHECKSUM) {
    lastSeqNum     = rxBuffer[PACKET_IDX_SEQ];
    lastChecksumOk = validateChecksum(rxBuffer);

    if (lastChecksumOk) {
      // Packet is intact — acknowledge and play the note
      Serial.write(ACK_BYTE);
      currentState = RxState::EXECUTING_ACTION;
      updateRxDisplay(currentState, lastSeqNum, true);
    } else {
      // Packet is corrupted by noise — request retransmission
      Serial.write(NACK_BYTE);
      bytesReceived = 0;
      currentState  = RxState::WAITING_FOR_START;
      updateRxDisplay(currentState, lastSeqNum, false);
    }
  }

  if (currentState == RxState::EXECUTING_ACTION) {
    decryptAndPlay(rxBuffer);
    bytesReceived = 0;
    currentState  = RxState::WAITING_FOR_START;
  }
}

// Arduino sketch entry points 
void setup() { rx_setup(); }
void loop()  { rx_loop();  }
