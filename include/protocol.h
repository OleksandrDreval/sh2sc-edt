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
