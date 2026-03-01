#pragma once

#include <stdint.h>

 
// SHARED PROTOCOL DEFINITIONS
// Used by both Transmitter (Node A) and Receiver (Node B)
 

// Packet structure 
// Each packet is exactly 5 bytes:
//   [0] START_MARKER | [1] enc_note_index | [2] enc_duration | [3] seq_num | [4] checksum
const uint8_t PACKET_SIZE         = 5;
const uint8_t PACKET_IDX_START    = 0;
const uint8_t PACKET_IDX_NOTE     = 1;
const uint8_t PACKET_IDX_DURATION = 2;
const uint8_t PACKET_IDX_SEQ      = 3;
const uint8_t PACKET_IDX_CHECKSUM = 4;

// Service bytes 
const uint8_t START_MARKER = 0xAA; // Frame delimiter; marks the beginning of a packet
const uint8_t ACK_BYTE     = 0x06; // Positive acknowledgement (packet received correctly)
const uint8_t NACK_BYTE    = 0x15; // Negative acknowledgement (checksum mismatch, resend)

// XOR stream cipher 
// Dynamic key formula: K_dynamic = SECRET_KEY ^ seq_num
// This prevents replay attacks because the same note produces different ciphertext
// each time it is sent with a different sequence number.
const uint8_t SECRET_KEY = 0x3F;

// Stop-and-Wait ARQ timing 
const uint32_t ACK_TIMEOUT_MS = 50UL;  // Max milliseconds to wait for ACK before retransmitting
const uint8_t  MAX_RETRIES    = 3;     // Maximum consecutive retransmissions before skipping note

// UART configuration 
const uint16_t BAUD_RATE = 9600;
