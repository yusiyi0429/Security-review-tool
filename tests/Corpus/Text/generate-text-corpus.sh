#!/usr/bin/env bash
# Generate text corpus files for parser testing.
# Produces Chinese canary text in various encodings, long lines,
# malformed sequences, and binary-window test files.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Chinese canary text for encoding tests
CANARY="你好世界！这是用于测试编码检测的中文文本。\n第二行包含更多的中文字符。\n第三行用于测试行号和列号映射。\n"

# UTF-8 (no BOM)
echo -n -e "$CANARY" > utf8_chinese.txt

# UTF-8 with BOM
printf '\xEF\xBB\xBF' > utf8_bom_chinese.txt
echo -n -e "$CANARY" >> utf8_bom_chinese.txt

# UTF-16LE with BOM
printf '\xFF\xFE' > utf16le_bom_chinese.txt
echo -n -e "$CANARY" | iconv -f UTF-8 -t UTF-16LE >> utf16le_bom_chinese.txt

# UTF-16BE with BOM
printf '\xFE\xFF' > utf16be_bom_chinese.txt
echo -n -e "$CANARY" | iconv -f UTF-8 -t UTF-16BE >> utf16be_bom_chinese.txt

# GB18030
echo -n -e "$CANARY" | iconv -f UTF-8 -t GB18030 > gb18030_chinese.txt 2>/dev/null || {
    echo "Warning: iconv GB18030 not supported, generating with Python"
    python3 -c "
import sys
text = '你好世界！这是用于测试编码检测的中文文本。\n第二行包含更多的中文字符。\n第三行用于测试行号和列号映射。\n'
with open('gb18030_chinese.txt', 'wb') as f:
    f.write(text.encode('gb18030'))
"
}

# Long line (>512 KiB) for chunker testing
python3 -c "
line = 'A' * 600_000 + '\n' + 'B' * 100 + '\n'
with open('long_line.txt', 'w', encoding='utf-8') as f:
    f.write(line)
print(f'Generated long_line.txt: {len(line)} chars')
"

# Malformed UTF-8 sequences
python3 -c "
# Valid UTF-8 prefix followed by invalid continuation bytes
data = bytearray('Hello '.encode('utf-8'))
data.extend(b'\xC0\x80')  # overlong NUL
data.extend(b'\xF5\x80\x80\x80')  # beyond Unicode range
data.extend(b'\xED\xA0\x80')  # surrogate half
data.extend(' World'.encode('utf-8'))
with open('malformed_utf8.bin', 'wb') as f:
    f.write(data)
print(f'Generated malformed_utf8.bin: {len(data)} bytes')
"

# ASCII + UTF-16 strings split across binary windows
python3 -c "
import struct

data = bytearray(2_000_000)  # 2 MiB, crosses 1 MiB window boundary

# Fill with random-ish bytes
import random
random.seed(42)
for i in range(len(data)):
    data[i] = random.randint(0, 255)

# Insert ASCII string near window boundary
ascii_str = b'ThisStringCrossesWindowBoundary!!'
offset = 1_048_576 - 10  # just before 1 MiB window end
data[offset:offset+len(ascii_str)] = ascii_str

# Insert UTF-16LE string
utf16le_str = 'CrossWindowUTF16'.encode('utf-16-le')
offset2 = 1_048_576 + 10
data[offset2:offset2+len(utf16le_str)] = utf16le_str

with open('binary_window_strings.bin', 'wb') as f:
    f.write(data)
print(f'Generated binary_window_strings.bin: {len(data)} bytes')
"

# High-entropy random binary (no text)
python3 -c "
import random, os
random.seed(99)
data = bytes(random.randint(0, 255) for _ in range(100_000))
with open('high_entropy_binary.bin', 'wb') as f:
    f.write(data)
print(f'Generated high_entropy_binary.bin: {len(data)} bytes')
"

echo "Corpus generation complete."
ls -la *.txt *.bin 2>/dev/null || true
