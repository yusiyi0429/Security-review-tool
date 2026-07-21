#!/usr/bin/env bash
# generate-binary-corpus.sh
# Generates PE32+/ELF32/ELF64 corpus fixtures for PeMetadataParser and
# ElfMetadataParser tests, plus high-entropy and overlapping-section edge
# cases. Output: tests/Corpus/Binary/
#
# The script is preserved by writing to a scratch directory and then moving
# the generated files into place.

set -euo pipefail

SCRIPT_PATH="$0"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR"

# Copy the script itself to a safe location before any cleanup so the
# generator does not delete itself.
SCRIPT_BACKUP="$(mktemp -t gen-bin-XXXXXX.sh)"
cp "$SCRIPT_PATH" "$SCRIPT_BACKUP"
chmod +x "$SCRIPT_BACKUP"

# Clean only generated files (not the script itself).
find "$CORPUS_DIR" -mindepth 1 -maxdepth 1 ! -name 'generate-binary-corpus.sh' -delete
mkdir -p "$CORPUS_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR" "$SCRIPT_BACKUP"' EXIT

echo "=== Generating binary corpus in $CORPUS_DIR ==="

# ---------- 1. minimal_pe32plus.bin ----------
echo "  minimal_pe32plus.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'minimal_pe32plus.bin')
canary = b'CANARY_PE32'
buf = bytearray()
buf += b'MZ'
buf += b'\x00' * 58
buf += struct.pack('<I', 64)
buf += b'PE\x00\x00'
buf += struct.pack('<H', 0x8664)
buf += struct.pack('<H', 2)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 240)
buf += struct.pack('<H', 0x0102)
buf += struct.pack('<H', 0x20B)
buf += struct.pack('<B', 14)
buf += struct.pack('<B', 0)
buf += b'\x00' * (240 - 4)
section_data_offset = 512
section_data_size = max(len(canary), 16)
section_data = canary.ljust(section_data_size, b'\x00')

buf += b'.text\x00\x00\x00'
buf += struct.pack('<I', section_data_size)
buf += struct.pack('<I', 0x1000)
buf += struct.pack('<I', section_data_size)
buf += struct.pack('<I', section_data_offset)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<I', 0x60000020)

section2_offset = section_data_offset + section_data_size
section2_size = 32
buf += b'.rdata\x00\x00'
buf += struct.pack('<I', section2_size)
buf += struct.pack('<I', 0x2000)
buf += struct.pack('<I', section2_size)
buf += struct.pack('<I', section2_offset)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<I', 0x40000040)

while len(buf) < section_data_offset:
    buf += b'\x00'

buf += section_data
buf += 'CANARY_PE_UTF16'.encode('utf-16-le').ljust(section2_size, b'\x00')

with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 2. minimal_elf32.bin ----------
echo "  minimal_elf32.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'minimal_elf32.bin')
strtab = b'\x00.shstrtab\x00CANARY_ELF32\x00'
shstrtab_size = len(strtab)

e_shoff = 52  # section headers immediately follow the header
buf = bytearray()
buf += b'\x7fELF'
buf += bytes([1, 1, 1, 0]) + b'\x00' * 8
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 3)
buf += struct.pack('<I', 1)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', e_shoff)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 52)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 40)
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 1)

# Section 0: null
buf += b'\x00' * 40
# Section 1: .shstrtab
buf += struct.pack('<I', 1)
buf += struct.pack('<I', 3)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', e_shoff + 80)  # immediately after both section headers
buf += struct.pack('<I', shstrtab_size)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 1)
buf += struct.pack('<I', 0)

# Strtab
buf += strtab

with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 3. minimal_elf64.bin ----------
echo "  minimal_elf64.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'minimal_elf64.bin')
strtab = b'\x00.shstrtab\x00CANARY_ELF64\x00'
shstrtab_size = len(strtab)

e_shoff = 64  # section headers immediately follow the header
buf = bytearray()
buf += b'\x7fELF'
buf += bytes([2, 1, 1, 0]) + b'\x00' * 8
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 62)
buf += struct.pack('<I', 1)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', e_shoff)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 64)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 64)
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 1)

# Section 0: null
buf += b'\x00' * 64
# Section 1: .shstrtab
buf += struct.pack('<I', 1)
buf += struct.pack('<I', 3)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', e_shoff + 64 * 2)  # after both section headers
buf += struct.pack('<Q', shstrtab_size)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<Q', 1)
buf += struct.pack('<Q', 0)

buf += strtab

with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 4. pe_overlapping_sections.bin ----------
echo "  pe_overlapping_sections.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'pe_overlapping_sections.bin')
buf = bytearray()
buf += b'MZ' + b'\x00' * 58 + struct.pack('<I', 64)
buf += b'PE\x00\x00'
buf += struct.pack('<H', 0x8664)
buf += struct.pack('<H', 2)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 240)
buf += struct.pack('<H', 0x0102)
buf += struct.pack('<H', 0x20B)
buf += b'\x00' * 238
buf += b'.text\x00\x00\x00'
buf += struct.pack('<I', 100)
buf += struct.pack('<I', 0x1000)
buf += struct.pack('<I', 100)
buf += struct.pack('<I', 512)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<I', 0x60000020)
buf += b'.data\x00\x00\x00'
buf += struct.pack('<I', 100)
buf += struct.pack('<I', 0x2000)
buf += struct.pack('<I', 100)
buf += struct.pack('<I', 512)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<I', 0xC0000040)
while len(buf) < 512:
    buf += b'\x00'
buf += b'A' * 200
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 5. pe_too_many_sections.bin ----------
echo "  pe_too_many_sections.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'pe_too_many_sections.bin')
buf = bytearray()
buf += b'MZ' + b'\x00' * 58 + struct.pack('<I', 64)
buf += b'PE\x00\x00'
buf += struct.pack('<H', 0x8664)
buf += struct.pack('<H', 200)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 240)
buf += struct.pack('<H', 0x0102)
buf += struct.pack('<H', 0x20B)
buf += b'\x00' * 238
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 6. pe_invalid_elfanew.bin ----------
echo "  pe_invalid_elfanew.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'pe_invalid_elfanew.bin')
buf = bytearray()
buf += b'MZ' + b'\x00' * 58 + struct.pack('<I', 0xFFFFFFFF)
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 7. elf_invalid_magic.bin ----------
echo "  elf_invalid_magic.bin"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'elf_invalid_magic.bin')
with open(out, 'wb') as f:
    f.write(b'\xDE\xAD\xBE\xEF' + b'\x00' * 200)
PY

# ---------- 8. elf_class_mismatch.bin ----------
echo "  elf_class_mismatch.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'elf_class_mismatch.bin')
buf = bytearray()
buf += b'\x7fELF'
buf += bytes([2, 1, 1, 0]) + b'\x00' * 8
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 62)
buf += struct.pack('<I', 1)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 64)  # e_shoff at 64
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 64)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 40)
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 1)
# Pad with 8 zero bytes (40 + 8 = 48, then place section at offset 64)
while len(buf) < 64:
    buf += b'\x00'
buf += b'\x00' * 40  # null section header at 64
# File ends with this 40-byte header, leaving room for additional content
# but with insufficient data for section 1 — the parser should reject.
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 9. high_entropy_random.bin ----------
echo "  high_entropy_random.bin"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'high_entropy_random.bin')
with open(out, 'wb') as f:
    f.write(os.urandom(8192))
PY

# ---------- 10. pe_zero_sections.bin ----------
echo "  pe_zero_sections.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'pe_zero_sections.bin')
buf = bytearray()
buf += b'MZ' + b'\x00' * 58 + struct.pack('<I', 64)
buf += b'PE\x00\x00'
buf += struct.pack('<H', 0x8664)
buf += struct.pack('<H', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 240)
buf += struct.pack('<H', 0x0102)
buf += struct.pack('<H', 0x20B)
buf += b'\x00' * 238
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 11. elf_with_build_id.bin ----------
echo "  elf_with_build_id.bin"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'elf_with_build_id.bin')
strtab = b'\x00.shstrtab\x00.note.gnu.build-id\x00'
shstrtab_size = len(strtab)

note = struct.pack('<III', 4, 20, 3) + b'GNU\x00' + b'\x00' * 20

e_shoff = 64  # section headers immediately follow the header
buf = bytearray()
buf += b'\x7fELF'
buf += bytes([2, 1, 1, 0]) + b'\x00' * 8
buf += struct.pack('<H', 2)
buf += struct.pack('<H', 62)
buf += struct.pack('<I', 1)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', e_shoff)
buf += struct.pack('<I', 0)
buf += struct.pack('<H', 64)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 0)
buf += struct.pack('<H', 64)
buf += struct.pack('<H', 3)
buf += struct.pack('<H', 1)

# Section 0: null
buf += b'\x00' * 64
# Section 1: .shstrtab
buf += struct.pack('<I', 1)
buf += struct.pack('<I', 3)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', e_shoff + 64 * 3)  # after all section headers
buf += struct.pack('<Q', shstrtab_size)
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<Q', 1)
buf += struct.pack('<Q', 0)
# Section 2: .note.gnu.build-id
note_name_off = 11
buf += struct.pack('<I', note_name_off)
buf += struct.pack('<I', 7)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', 0)
buf += struct.pack('<Q', e_shoff + 64 * 3 + shstrtab_size)
buf += struct.pack('<Q', len(note))
buf += struct.pack('<I', 0)
buf += struct.pack('<I', 0)
buf += struct.pack('<Q', 4)
buf += struct.pack('<Q', 0)

buf += strtab + note
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

echo "=== Binary corpus generation complete ==="
ls -la "$CORPUS_DIR"