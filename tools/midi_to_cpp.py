#!/usr/bin/env python3

"""
midi_to_cpp.py - MIDI to C++ array converter for Arduino melody playback.

Converts a monophonic MIDI file into C++ static arrays compatible with
the Arduino receiver node's 21-note dictionary (C4 to G#5).

Usage:
    python midi_to_cpp.py <path_to_file.mid>
    python midi_to_cpp.py <path_to_file.mid> --start 10 --end 30
    python midi_to_cpp.py          # will prompt for path interactively
"""

import sys
import argparse
from pathlib import Path
from collections import defaultdict

try:
    import mido
except ImportError:
    print("Error: 'mido' library is not installed.")
    print("Run: pip install mido")
    sys.exit(1)


# Constants

MIDI_NOTE_C4 = 60       # Lowest note in our dictionary → index 0
MIDI_NOTE_GS5 = 80      # Highest note → index 20
DICT_SIZE = MIDI_NOTE_GS5 - MIDI_NOTE_C4 + 1   # 21 notes

REST_INDEX = 255            # Special sentinel: silence / pause
DEFAULT_TEMPO_US = 500_000  # 120 BPM in microseconds per beat
NOTES_PER_OCTAVE = 12

# Human-readable names aligned with receiver's dictionary indices 0-20
NOTE_NAMES = [
    "C4", "C#4", "D4",  "D#4", "E4", "F4",  "F#4", "G4",  "G#4",
    "A4", "A#4", "B4",  "C5",  "C#5","D5",  "D#5", "E5",  "F5",
    "F#5","G5",  "G#5",
]


# Note utilities

def transpose_into_range(midi_note: int) -> int:
    """
    Transpose a MIDI note number into [MIDI_NOTE_C4, MIDI_NOTE_GS5]
    by shifting up or down by full octaves.
    """
    while midi_note < MIDI_NOTE_C4:
        midi_note += NOTES_PER_OCTAVE
    while midi_note > MIDI_NOTE_GS5:
        midi_note -= NOTES_PER_OCTAVE
    return midi_note


def midi_note_to_index(midi_note: int) -> int:
    """
    Map a MIDI note number to an Arduino dictionary index (0-20).
    Automatically transposes out-of-range notes by octave.
    """
    return transpose_into_range(midi_note) - MIDI_NOTE_C4


def index_to_name(index: int) -> str:
    """Return a human-readable note name for a dictionary index."""
    if index == REST_INDEX:
        return "Pause"
    if 0 <= index < DICT_SIZE:
        return NOTE_NAMES[index]
    return f"idx{index}"


# Tempo map

def build_tempo_map(midi_file: mido.MidiFile) -> list[tuple[int, int]]:
    """
    Scan all tracks for set_tempo meta messages and build a sorted
    list of (absolute_tick, tempo_us_per_beat) change points.
    Track 0 in type-1 files typically holds all tempo events.
    """
    changes: list[tuple[int, int]] = []

    for track in midi_file.tracks:
        absolute_tick = 0
        for msg in track:
            absolute_tick += msg.time
            if msg.type == "set_tempo":
                changes.append((absolute_tick, msg.tempo))

    # Sort by tick and prepend the default tempo at tick 0
    changes.sort(key=lambda x: x[0])
    if not changes or changes[0][0] != 0:
        changes.insert(0, (0, DEFAULT_TEMPO_US))

    return changes


def ticks_range_to_ms(
    start_tick: int,
    end_tick: int,
    tempo_map: list[tuple[int, int]],
    ticks_per_beat: int,
) -> int:
    """
    Convert a tick interval [start_tick, end_tick) to milliseconds,
    respecting all tempo changes that fall within that interval.
    """
    if start_tick >= end_tick or ticks_per_beat == 0:
        return 0

    total_us = 0

    for i, (map_tick, tempo_us) in enumerate(tempo_map):
        segment_start = max(start_tick, map_tick)
        segment_end = end_tick if (i + 1 >= len(tempo_map)) else min(end_tick, tempo_map[i + 1][0])

        if segment_start >= segment_end:
            continue
        if segment_end <= start_tick:
            continue

        tick_count = segment_end - segment_start
        total_us += (tick_count * tempo_us) // ticks_per_beat

    return total_us // 1000


# MIDI track selection and monophonic extraction

def find_first_note_track(midi_file: mido.MidiFile) -> mido.MidiTrack | None:
    """Return the first track that contains at least one note_on event."""
    for track in midi_file.tracks:
        for msg in track:
            if msg.type == "note_on" and msg.velocity > 0:
                return track
    return None


def extract_monophonic_events(track: mido.MidiTrack) -> list[tuple[int, str, int]]:
    """
    Convert a MIDI track into a flat list of (absolute_tick, event_type, note).
    event_type is either "on" or "off".
    """
    events: list[tuple[int, str, int]] = []
    absolute_tick = 0

    for msg in track:
        absolute_tick += msg.time

        if msg.type == "note_on" and msg.velocity > 0:
            events.append((absolute_tick, "on", msg.note))
        elif msg.type == "note_off" or (msg.type == "note_on" and msg.velocity == 0):
            events.append((absolute_tick, "off", msg.note))

    return events


def build_melody(
    events: list[tuple[int, str, int]],
    tempo_map: list[tuple[int, int]],
    ticks_per_beat: int,
) -> list[tuple[int, int]]:
    """
    Convert raw note events into a (note_index, duration_ms) sequence.

    Chord handling: when multiple notes sound simultaneously, the highest
    MIDI number is selected (most prominent melodic note).
    Gaps between notes are emitted as REST_INDEX entries.
    Segments shorter than 1 ms are silently merged into the next event.
    """
    if not events:
        return []

    # Group events by absolute tick so we can process each boundary once
    tick_map: dict[int, list[tuple[str, int]]] = defaultdict(list)
    for tick, etype, note in events:
        tick_map[tick].append((etype, note))

    sorted_ticks = sorted(tick_map.keys())

    melody: list[tuple[int, int]] = []
    active_notes: set[int] = set()
    prev_tick = 0

    for tick in sorted_ticks:
        delta_ticks = tick - prev_tick

        if delta_ticks > 0:
            duration_ms = ticks_range_to_ms(prev_tick, tick, tempo_map, ticks_per_beat)
            if duration_ms > 0:
                if active_notes:
                    # Monophonic selection: highest note wins
                    note_index = midi_note_to_index(max(active_notes))
                    melody.append((note_index, duration_ms))
                else:
                    melody.append((REST_INDEX, duration_ms))

        # Apply all events that happen at this tick
        for etype, note in tick_map[tick]:
            if etype == "on":
                active_notes.add(note)
            else:
                active_notes.discard(note)

        prev_tick = tick

    return melody


# Time slicing

def slice_melody(
    melody: list[tuple[int, int]],
    start_ms: float,
    end_ms: float | None,
) -> list[tuple[int, int]]:
    """
    Return the portion of melody that falls within [start_ms, end_ms).

    - Entries entirely before start_ms are skipped.
    - The first kept entry is clipped so no huge leading pause is emitted.
    - Processing stops as soon as accumulated time reaches end_ms.
    """
    result: list[tuple[int, int]] = []
    accumulated_ms: float = 0.0

    for note_index, duration_ms in melody:
        entry_start = accumulated_ms
        entry_end = accumulated_ms + duration_ms
        accumulated_ms = entry_end

        # Entirely before the window: skip
        if entry_end <= start_ms:
            continue

        # Entirely after the window: stop
        if end_ms is not None and entry_start >= end_ms:
            break

        # Clip the entry to fit within [start_ms, end_ms)
        clipped_start = max(entry_start, start_ms)
        clipped_end = entry_end if end_ms is None else min(entry_end, end_ms)
        clipped_duration = int(clipped_end - clipped_start)

        if clipped_duration > 0:
            result.append((note_index, clipped_duration))

    return result


# Maximum number of entries written to melody.h.
# 3500 entries × 4 bytes = 14 000 bytes of Flash — well within the ATmega328P
# 32 KB limit after sketch overhead.
MAX_NOTES = 3500


# C++ code generation

def render_cpp(melody: list[tuple[int, int]], source_name: str) -> str:
    """Render the melody as a PROGMEM C++ header ready to drop into a sketch."""
    # Truncate if necessary and warn the user.
    if len(melody) > MAX_NOTES:
        print(
            f"Warning: melody has {len(melody)} entries — "
            f"truncating to MAX_NOTES={MAX_NOTES} to fit in Flash.",
            file=sys.stderr,
        )
        melody = melody[:MAX_NOTES]

    flash_bytes = len(melody) * 4  # 2 × uint16_t per row
    lines: list[str] = []

    lines.append("#pragma once")
    lines.append("")
    lines.append("// melody.h — Melody data for TransmitterNode.")
    lines.append("//")
    lines.append("// THIS FILE IS AUTO-GENERATED by tools/midi_to_cpp.py.")
    lines.append("// Do NOT edit by hand — re-run the script to update the melody.")
    lines.append("//")
    lines.append("// Format of melody[][2]:")
    lines.append("//   Column 0 — note index (uint16_t):")
    lines.append("//               0–20 = chromatic pitches C4…G#5.")
    lines.append("//               255  = REST / silence.")
    lines.append("//   Column 1 — duration in milliseconds (uint16_t).")
    lines.append("//")
    lines.append(f"// Source MIDI : {source_name}")
    lines.append(f"// Notes       : {len(melody)}")
    lines.append(f"// Flash usage : {len(melody)} x 4 bytes = {flash_bytes} bytes of PROGMEM")
    lines.append("")
    lines.append("#include <Arduino.h>")
    lines.append("#include <avr/pgmspace.h>  // pgm_read_word() — required to read PROGMEM data on AVR")
    lines.append("")
    lines.append("// Total number of note / rest entries in the melody table.")
    lines.append(f"// Flash usage: MELODY_LENGTH x 4 bytes (two uint16_t per row) = ~{flash_bytes} bytes of Flash.")
    lines.append(f"static const uint16_t MELODY_LENGTH = {len(melody)};")
    lines.append("")
    lines.append("// melody[i][0] = note index,  melody[i][1] = duration (ms)")
    lines.append("// Stored in Flash (PROGMEM) to avoid consuming SRAM.")
    lines.append("// Access via pgm_read_word(&melody[i][col]) — do NOT dereference directly.")
    lines.append("static const uint16_t melody[MELODY_LENGTH][2] PROGMEM = {")

    for note_index, duration_ms in melody:
        name = index_to_name(note_index)
        lines.append(f"    {{{note_index:3d}, {duration_ms:5d}}},  // {name}, {duration_ms} ms")

    lines.append("};")
    return "\n".join(lines)


# Main entry point

def convert(
    midi_path: str,
    start_s: float = 0.0,
    end_s: float | None = None,
) -> None:
    """Load, parse, and print the C++ representation of a MIDI file."""
    path = Path(midi_path)

    if not path.exists():
        print(f"Error: File not found — '{path}'", file=sys.stderr)
        sys.exit(1)

    if path.suffix.lower() != ".mid":
        print(f"Warning: '{path.name}' does not have a .mid extension, proceeding anyway.")

    midi_file = mido.MidiFile(str(path))

    if midi_file.ticks_per_beat == 0:
        print("Error: MIDI file has ticks_per_beat = 0, cannot compute timing.", file=sys.stderr)
        sys.exit(1)

    tempo_map = build_tempo_map(midi_file)
    note_track = find_first_note_track(midi_file)

    if note_track is None:
        print("Error: No tracks with note data found in the MIDI file.", file=sys.stderr)
        sys.exit(1)

    raw_events = extract_monophonic_events(note_track)
    melody = build_melody(raw_events, tempo_map, midi_file.ticks_per_beat)

    if not melody:
        print("Error: Could not extract any notes from the MIDI file.", file=sys.stderr)
        sys.exit(1)

    # Apply time slicing when start/end are explicitly requested
    start_ms = start_s * 1000.0
    end_ms = end_s * 1000.0 if end_s is not None else None
    melody = slice_melody(melody, start_ms, end_ms)

    if not melody:
        print(
            f"Error: No notes found in the time range "
            f"{start_s}s – {end_s if end_s is not None else 'end'}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Format the trim range for the summary line
    end_label = f"{end_s}s" if end_s is not None else "end"
    trim_label = f"{start_s}s to {end_label}"

    # --- Summary to stderr so it doesn't pollute the C++ stdout output ---
    print(f"// Source  : {path.name}", file=sys.stderr)
    print(f"// Notes   : {len(melody)}", file=sys.stderr)
    print(f"// Tempo   : {DEFAULT_TEMPO_US // 1000} BPM base "
          f"({len(tempo_map)} tempo segment(s))", file=sys.stderr)
    print(f"// Ticks/beat: {midi_file.ticks_per_beat}", file=sys.stderr)
    print(f"// Trim    : {trim_label}", file=sys.stderr)
    print("", file=sys.stderr)

    print(render_cpp(melody, path.name))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a MIDI file to a C++ array for Arduino monophonic playback.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python midi_to_cpp.py mario.mid\n"
            "  python midi_to_cpp.py mario.mid --start 10 --end 30\n"
            "  python midi_to_cpp.py mario.mid -s 5.5\n"
            "  python midi_to_cpp.py          # interactive prompt\n"
        ),
    )
    parser.add_argument(
        "midi_file",
        nargs="?",
        help="Path to the .mid file to convert.",
    )
    parser.add_argument(
        "-s", "--start",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Start time in seconds (default: 0).",
    )
    parser.add_argument(
        "-e", "--end",
        type=float,
        default=None,
        metavar="SEC",
        help="End time in seconds (default: end of file).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    midi_path = args.midi_file
    if not midi_path:
        midi_path = input("Enter path to .mid file: ").strip()

    if not midi_path:
        print("Error: No file path provided.", file=sys.stderr)
        sys.exit(1)

    convert(midi_path, start_s=args.start, end_s=args.end)


if __name__ == "__main__":
    main()
