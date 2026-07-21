#!/usr/bin/env bash
# generate-jvm-corpus.sh
# Generates JVM/JAR corpus fixtures for JvmClassParser tests.
# Output: tests/Corpus/Jvm/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR"

# Preserve the script before cleanup.
cp "$0" /tmp/gen-jvm-preserve.sh

rm -rf "$CORPUS_DIR"
mkdir -p "$CORPUS_DIR"

# Restore the script.
cp /tmp/gen-jvm-preserve.sh "$CORPUS_DIR/generate-jvm-corpus.sh"
chmod +x "$CORPUS_DIR/generate-jvm-corpus.sh"
rm /tmp/gen-jvm-preserve.sh

echo "=== Generating JVM corpus in $CORPUS_DIR ==="

# ---------- 1. valid_hello.class ----------
echo "  valid_hello.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'valid_hello.class')
def utf8(s):
    data = s.encode('utf-8')
    return bytes([1]) + struct.pack('>H', len(data)) + data
def cls(i):
    return bytes([7]) + struct.pack('>H', i)
pool = utf8('demo/Hello') + cls(1) + utf8('<init>') + utf8('()V') + utf8('Code') + utf8('java/lang/Object') + cls(6)
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
cnt = struct.pack('>H', 8)
post = struct.pack('>HHH', 0x0021, 2, 7)
with open(out, 'wb') as f:
    f.write(header + ver + cnt + pool + post)
PY

# ---------- 2. valid_lib.jar ----------
echo "  valid_lib.jar"
python3 - <<PY
import zipfile, os
out = os.path.join('$CORPUS_DIR', 'valid_lib.jar')
cls_path = os.path.join('$CORPUS_DIR', 'valid_hello.class')
with open(cls_path, 'rb') as f:
    cls_bytes = f.read()
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nMain-Class: demo.Hello\n')
    z.writestr('demo/Hello.class', cls_bytes)
    z.writestr('demo/resource.txt', 'hello resource')
PY

# ---------- 3. invalid_magic.class ----------
echo "  invalid_magic.class"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'invalid_magic.class')
with open(out, 'wb') as f:
    f.write(b'\xDE\xAD\xBE\xEF' + b'\x00' * 200)
PY

# ---------- 4. unknown_major_version.class ----------
echo "  unknown_major_version.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'unknown_major_version.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 999)
cnt = struct.pack('>H', 1)
with open(out, 'wb') as f:
    f.write(header + ver + cnt + b'\x01\x00\x00')
PY

# ---------- 5. constant_pool_overflow.class ----------
echo "  constant_pool_overflow.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'constant_pool_overflow.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
cnt = struct.pack('>H', 0)
with open(out, 'wb') as f:
    f.write(header + ver + cnt + b'\x00' * 8)
PY

# ---------- 6. huge_utf8_entry.class ----------
echo "  huge_utf8_entry.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'huge_utf8_entry.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
cnt = struct.pack('>H', 2)
tag = bytes([1])
length = struct.pack('>H', 0xFFFF)
data = b'A' * 0xFFFF
with open(out, 'wb') as f:
    f.write(header + ver + cnt + tag + length + data)
PY

# ---------- 7. malformed_utf8.class ----------
echo "  malformed_utf8.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'malformed_utf8.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
cnt = struct.pack('>H', 2)
tag = bytes([1])
length = struct.pack('>H', 2)
data = bytes([0xC2, 0x00])
with open(out, 'wb') as f:
    f.write(header + ver + cnt + tag + length + data)
PY

# ---------- 8. unknown_tag.class ----------
echo "  unknown_tag.class"
python3 - <<PY
import os, struct
out = os.path.join('$CORPUS_DIR', 'unknown_tag.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
cnt = struct.pack('>H', 3)
def utf8(s):
    data = s.encode('utf-8')
    return bytes([1]) + struct.pack('>H', len(data)) + data
body = utf8('x') + bytes([0x66]) + b'\x00' * 10
with open(out, 'wb') as f:
    f.write(header + ver + cnt + body)
PY

# ---------- 9. truncated.class ----------
echo "  truncated.class"
python3 - <<PY
import os, struct
out = os.path.join('$CORPUS_DIR', 'truncated.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
cnt = struct.pack('>H', 5)
def utf8(s):
    data = s.encode('utf-8')
    return bytes([1]) + struct.pack('>H', len(data)) + data
with open(out, 'wb') as f:
    f.write(header + ver + cnt + utf8('x'))
PY

# ---------- 10. nested_jar.jar ----------
echo "  nested_jar.jar"
python3 - <<PY
import zipfile, os, struct
inner = os.path.join('/tmp', '_nested_inner_' + os.path.basename('$CORPUS_DIR') + '.jar')
with zipfile.ZipFile(inner, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('payload.txt', 'inner secret')

def cls_bytes(name):
    def utf8(s):
        data = s.encode('utf-8')
        return bytes([1]) + struct.pack('>H', len(data)) + data
    def cls(i):
        return bytes([7]) + struct.pack('>H', i)
    pool = utf8(name) + cls(1) + utf8('<init>') + utf8('()V') + utf8('java/lang/Object') + cls(4)
    header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
    return header + struct.pack('>HHH', 0, 52, 6) + pool + struct.pack('>HHH', 0x0021, 2, 5)

outer = os.path.join('$CORPUS_DIR', 'nested_jar.jar')
with zipfile.ZipFile(outer, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')
    z.writestr('demo/Outer.class', cls_bytes('demo/Outer'))
    with open(inner, 'rb') as f:
        z.writestr('lib/inner.jar', f.read())
os.remove(inner)
PY

# ---------- 11. name_and_type.class ----------
echo "  name_and_type.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'name_and_type.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
def utf8(s):
    data = s.encode('utf-8')
    return bytes([1]) + struct.pack('>H', len(data)) + data
def nt(n, d):
    return bytes([12]) + struct.pack('>HH', n, d)
body = utf8('<init>') + utf8('()V') + nt(1, 2)
cnt = struct.pack('>H', 4)
with open(out, 'wb') as f:
    f.write(header + ver + cnt + body)
PY

# ---------- 12. module_package.class ----------
echo "  module_package.class"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'module_package.class')
header = bytes([0xCA, 0xFE, 0xBA, 0xBE])
ver = struct.pack('>HH', 0, 52)
def utf8(s):
    data = s.encode('utf-8')
    return bytes([1]) + struct.pack('>H', len(data)) + data
def mod(i):
    return bytes([19]) + struct.pack('>H', i)
def pkg(i):
    return bytes([20]) + struct.pack('>H', i)
body = utf8('java.base') + mod(1) + utf8('java.lang') + pkg(3)
cnt = struct.pack('>H', 5)
with open(out, 'wb') as f:
    f.write(header + ver + cnt + body)
PY

echo "=== JVM corpus generation complete ==="
ls -la "$CORPUS_DIR"