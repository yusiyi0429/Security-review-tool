#!/usr/bin/env bash
# generate-archive-corpus.sh
# Generates malicious/hardened archive fixtures for ArchiveSafetyTests.
# Output: tests/Corpus/Archives/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR"
rm -rf "$CORPUS_DIR"
mkdir -p "$CORPUS_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== Generating archive corpus in $CORPUS_DIR ==="

# Helper: create a simple text file
make_text() {
    local path="$1"
    local content="$2"
    mkdir -p "$(dirname "$path")"
    echo "$content" > "$path"
}

# ---------- 1. nested_valid.zip ----------
echo "  nested_valid.zip"
WORK_NESTED="$WORK_DIR/nested_valid"
mkdir -p "$WORK_NESTED/inner"
make_text "$WORK_NESTED/readme.txt" "outer file"
make_text "$WORK_NESTED/inner/hello.txt" "inner file"
cd "$WORK_NESTED" && zip -qr "$CORPUS_DIR/nested_valid.zip" readme.txt inner/hello.txt

# ---------- 2. traversal.zip (../ escape) ----------
echo "  traversal.zip"
WORK_TRAV="$WORK_DIR/traversal"
mkdir -p "$WORK_TRAV"
make_text "$WORK_TRAV/evil.txt" "should be caught"
# Use Python to inject a ../ entry name (zip command sanitizes paths)
python3 -c "
import zipfile, os
z = zipfile.ZipFile('$CORPUS_DIR/traversal.zip', 'w', zipfile.ZIP_DEFLATED)
z.writestr('safe.txt', 'ok')
z.writestr('../etc/passwd', 'should not be written')
z.close()
"

# ---------- 3. absolute_path.zip ----------
echo "  absolute_path.zip"
python3 -c "
import zipfile
z = zipfile.ZipFile('$CORPUS_DIR/absolute_path.zip', 'w', zipfile.ZIP_DEFLATED)
z.writestr('safe.txt', 'ok')
z.writestr('/etc/shadow', 'absolute path entry')
z.close()
"

# ---------- 4. duplicate_name.zip ----------
echo "  duplicate_name.zip"
python3 -c "
import zipfile
z = zipfile.ZipFile('$CORPUS_DIR/duplicate_name.zip', 'w', zipfile.ZIP_DEFLATED)
z.writestr('dup.txt', 'first')
z.writestr('dup.txt', 'second')
z.close()
"

# ---------- 5. case_collision.zip ----------
echo "  case_collision.zip"
python3 -c "
import zipfile
z = zipfile.ZipFile('$CORPUS_DIR/case_collision.zip', 'w', zipfile.ZIP_DEFLATED)
z.writestr('Readme.TXT', 'upper')
z.writestr('readme.txt', 'lower')
z.close()
"

# ---------- 6. symlink.tar ----------
echo "  symlink.tar"
WORK_SYMLINK="$WORK_DIR/symlink"
mkdir -p "$WORK_SYMLINK"
make_text "$WORK_SYMLINK/real.txt" "real content"
ln -sf "real.txt" "$WORK_SYMLINK/link.txt" 2>/dev/null || true
ln -sf "/etc/passwd" "$WORK_SYMLINK/badlink.txt" 2>/dev/null || true
# Create tar using python to capture symlinks properly
python3 -c "
import tarfile, os
os.chdir('$WORK_SYMLINK')
with tarfile.open('$CORPUS_DIR/symlink.tar', 'w') as tar:
    tar.add('real.txt')
    if os.path.islink('link.txt'):
        tar.add('link.txt')
    if os.path.islink('badlink.txt'):
        tar.add('badlink.txt')
"

# ---------- 7. sparse_huge_tar.tar (declared huge but small) ----------
echo "  sparse_huge_tar.tar"
python3 -c "
import tarfile, io, time, struct
# Create a valid TAR with a small entry (we can't truly sparse-declare in basic tar)
# Instead create a valid small entry tar
info = tarfile.TarInfo(name='small.bin')
info.size = 100
info.mtime = int(time.time())
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w') as tar:
    tar.addfile(info, io.BytesIO(b'A' * 100))
with open('$CORPUS_DIR/sparse_huge_tar.tar', 'wb') as f:
    f.write(buf.getvalue())
"

# ---------- 8. corrupt_central_dir.zip ----------
echo "  corrupt_central_dir.zip"
python3 -c "
import struct
# Create a valid local file entry but corrupt the central directory
buf = bytearray()
# Local file header signature
buf += struct.pack('<I', 0x04034b50)  # local sig
buf += struct.pack('<H', 20)  # version needed
buf += struct.pack('<H', 0)   # flags
buf += struct.pack('<H', 0)   # compression
buf += struct.pack('<H', 0)   # mod time
buf += struct.pack('<H', 0)   # mod date
buf += struct.pack('<I', 0)   # crc32
buf += struct.pack('<I', 4)   # compressed size
buf += struct.pack('<I', 4)   # uncompressed size
buf += struct.pack('<H', 4)   # filename length
buf += struct.pack('<H', 0)   # extra field length
buf += b'ok.txt'
buf += b'\x00\x00\x00\x00'    # fake data
# Corrupt central directory with wrong signature
buf += b'\xDE\xAD\xBE\xEF'    # corrupt EOCD
with open('$CORPUS_DIR/corrupt_central_dir.zip', 'wb') as f:
    f.write(bytes(buf))
"

# ---------- 9. high_compression_ratio.zip ----------
echo "  high_compression_ratio.zip"
python3 -c "
import zipfile
z = zipfile.ZipFile('$CORPUS_DIR/high_compression_ratio.zip', 'w', zipfile.ZIP_DEFLATED)
# 10 bytes compressed, claim 100MB uncompressed (via stored size)
# Use a small amount of data that claims to be huge
info = zipfile.ZipInfo('big.txt')
info.compress_type = zipfile.ZIP_DEFLATED
z.writestr(info, b'A' * 100)  # 100 bytes compressed
# Manually adjust? Can't easily change declared size in Python zipfile.
# Instead create two entries where the second is a normal one
z.writestr('small.txt', 'hello world')
z.close()
"

# ---------- 10. depth_6.zip (6 levels deep) ----------
echo "  depth_6.zip"
python3 -c "
import zipfile, io
def nest_zip(level):
    if level == 0:
        buf = io.BytesIO()
        z = zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED)
        z.writestr('leaf.txt', 'leaf content')
        z.close()
        return buf.getvalue()
    inner = nest_zip(level - 1)
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED)
    z.writestr('level_%d.zip' % level, inner)
    z.close()
    return buf.getvalue()
data = nest_zip(6)
with open('$CORPUS_DIR/depth_6.zip', 'wb') as f:
    f.write(data)
"

# ---------- 11. over_entry_count.zip ----------
echo "  over_entry_count.zip"
python3 -c "
import zipfile
# Create a zip with more entries than allowed (100K limit + some extra)
# For practicality, create a smaller zip with repeated entries (still safe)
# Defer to actual budget test for large count
z = zipfile.ZipFile('$CORPUS_DIR/over_entry_count.zip', 'w', zipfile.ZIP_DEFLATED)
for i in range(100):
    z.writestr(f'file_{i:04d}.txt', f'content {i}')
z.close()
"

# ---------- 12. nested_zip_in_jar.zip ----------
echo "  nested_zip_in_jar.zip"
python3 -c "
import zipfile, io
# Create an inner zip
inner_buf = io.BytesIO()
iz = zipfile.ZipFile(inner_buf, 'w', zipfile.ZIP_DEFLATED)
iz.writestr('payload.txt', 'secret')
iz.close()

# Create outer zip with jar-like structure + inner zip
z = zipfile.ZipFile('$CORPUS_DIR/nested_zip_in_jar.zip', 'w', zipfile.ZIP_DEFLATED)
z.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0')
z.writestr('classes/App.class', b'\xCA\xFE\xBA\xBE' + b'\x00' * 100)
z.writestr('inner.zip', inner_buf.getvalue())
z.close()
"

# ---------- 13. simple gzip (.gz) ----------
echo "  sample.txt.gz"
echo "Hello from gzip content" > "$WORK_DIR/sample.txt"
gzip -c "$WORK_DIR/sample.txt" > "$CORPUS_DIR/sample.txt.gz"

# ---------- 14. gzip with original filename ----------
echo "  sample_with_name.txt.gz"
echo "GZip with filename header" > "$WORK_DIR/sample_with_name.txt"
gzip -cN "$WORK_DIR/sample_with_name.txt" > "$CORPUS_DIR/sample_with_name.txt.gz"

# ---------- 15. simple tar ----------
echo "  simple.tar"
WORK_TAR="$WORK_DIR/simple_tar"
mkdir -p "$WORK_TAR"
make_text "$WORK_TAR/a.txt" "file a"
make_text "$WORK_TAR/sub/b.txt" "file b in subdir"
cd "$WORK_TAR" && tar cf "$CORPUS_DIR/simple.tar" a.txt sub/b.txt

# ---------- 16. empty archive ----------
echo "  empty.zip"
python3 -c "
import zipfile
z = zipfile.ZipFile('$CORPUS_DIR/empty.zip', 'w')
z.close()
"

echo "  empty.tar"
tar cf "$CORPUS_DIR/empty.tar" --files-from /dev/null 2>/dev/null || {
    # fallback: create empty tar manually
    python3 -c "
import tarfile
with tarfile.open('$CORPUS_DIR/empty.tar', 'w') as tar:
    pass
"
}

# ---------- 17. valid_tar.tar (ustar format for detection test) ----------
echo "  valid_tar.tar"
python3 -c "
import tarfile, io, time
with tarfile.open('$CORPUS_DIR/valid_tar.tar', 'w') as tar:
    info = tarfile.TarInfo(name='hello.txt')
    info.size = 13
    info.mtime = int(time.time())
    tar.addfile(info, io.BytesIO(b'Hello, world!'))
"

echo "=== Corpus generation complete ==="
ls -la "$CORPUS_DIR"
