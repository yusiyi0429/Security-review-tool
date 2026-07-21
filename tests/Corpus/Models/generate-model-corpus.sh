#!/usr/bin/env bash
# generate-model-corpus.sh
# Generates safe and dangerous model corpus fixtures for model metadata parsers.
# Uses python3 to produce byte-level artifacts — no real PyTorch/GGUF/ONNX frameworks.
# Output: tests/Corpus/Models/

set -euo pipefail

SCRIPT_PATH="$0"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR"

# Copy the script itself to a safe location before any cleanup
SCRIPT_BACKUP="$(mktemp -t gen-model-XXXXXX.sh)"
cp "$SCRIPT_PATH" "$SCRIPT_BACKUP"
chmod +x "$SCRIPT_BACKUP"

# Clean only generated files (not the script itself)
find "$CORPUS_DIR" -mindepth 1 -maxdepth 1 ! -name 'generate-model-corpus.*' -delete
mkdir -p "$CORPUS_DIR"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR" "$SCRIPT_BACKUP"' EXIT

echo "=== Generating model corpus in $CORPUS_DIR ==="

# ---------- 1. safetensors_minimal.safetensors ----------
echo "  safetensors_minimal.safetensors"
python3 - <<PY
import struct, json, os
out = os.path.join('$CORPUS_DIR', 'safetensors_minimal.safetensors')
meta = {
    'weight': {'dtype': 'F32', 'shape': [2, 3], 'data_offsets': [0, 24]},
    '__metadata__': {'model': 'test', 'framework': 'safetensors-rs'}
}
header = json.dumps(meta).encode('utf-8')
header_len = len(header)
tensor_data = struct.pack('<6f', 1.0, 2.0, 3.0, 4.0, 5.0, 6.0)
with open(out, 'wb') as f:
    f.write(struct.pack('<Q', header_len))
    f.write(header)
    f.write(tensor_data)
PY

# ---------- 2. safetensors_oversized_header.safetensors ----------
echo "  safetensors_oversized_header.safetensors"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'safetensors_oversized_header.safetensors')
# Claim header length > 100 MiB (104_857_600 bytes)
with open(out, 'wb') as f:
    f.write(struct.pack('<Q', 104_857_601))
    f.write(b'\x00' * 64)
PY

# ---------- 3. safetensors_truncated.safetensors ----------
echo "  safetensors_truncated.safetensors"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'safetensors_truncated.safetensors')
# Claim header is 200 bytes, but only write 8-byte length + 1 byte
with open(out, 'wb') as f:
    f.write(struct.pack('<Q', 200))
    f.write(b'{')
PY

# ---------- 4. safetensors_with_canary_weights.safetensors ----------
echo "  safetensors_with_canary_weights.safetensors"
python3 - <<PY
import struct, json, os
out = os.path.join('$CORPUS_DIR', 'safetensors_with_canary_weights.safetensors')
canary = b'ENCRYPTED_SECRET_CANARY'
meta = {
    'canary_tensor': {'dtype': 'U8', 'shape': [len(canary)], 'data_offsets': [0, len(canary)]}
}
header = json.dumps(meta).encode('utf-8')
with open(out, 'wb') as f:
    f.write(struct.pack('<Q', len(header)))
    f.write(header)
    f.write(canary)
PY

# ---------- 5. gguf_v3_minimal.gguf ----------
echo "  gguf_v3_minimal.gguf"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'gguf_v3_minimal.gguf')
buf = bytearray()
buf += b'GGUF'
buf += struct.pack('<I', 3)        # version 3
buf += struct.pack('<Q', 1)        # tensor_count = 1
buf += struct.pack('<Q', 2)        # metadata_kv_count = 2

# KV 1: key="general.architecture" value="llama" (STRING type=9)
key1 = b'general.architecture'
val1 = b'llama'
buf += struct.pack('<Q', len(key1))
buf += key1
buf += struct.pack('<I', 9)         # STRING
buf += struct.pack('<Q', len(val1))
buf += val1

# KV 2: key="general.name" value="test-model" (STRING type=9)
key2 = b'general.name'
val2 = b'test-model'
buf += struct.pack('<Q', len(key2))
buf += key2
buf += struct.pack('<I', 9)         # STRING
buf += struct.pack('<Q', len(val2))
buf += val2

# Tensor info: name="output.weight", n_dims=2, shape=[4, 4], type=F32(1), offset=0
tname = b'output.weight'
buf += struct.pack('<Q', len(tname))
buf += tname
buf += struct.pack('<I', 2)         # n_dims
buf += struct.pack('<Q', 4)         # dim 0
buf += struct.pack('<Q', 4)         # dim 1
buf += struct.pack('<I', 1)         # type = F32
buf += struct.pack('<Q', 0)         # offset

# Align to 32 bytes
while len(buf) % 32 != 0:
    buf += b'\x00'

with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 6. gguf_v2_minimal.gguf ----------
echo "  gguf_v2_minimal.gguf"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'gguf_v2_minimal.gguf')
buf = bytearray()
buf += b'GGUF'
buf += struct.pack('<I', 2)        # version 2
buf += struct.pack('<Q', 0)        # tensor_count = 0
buf += struct.pack('<Q', 1)        # metadata_kv_count = 1

# KV: key="tokenizer.ggml.model", value="gpt2"
key1 = b'tokenizer.ggml.model'
val1 = b'gpt2'
buf += struct.pack('<Q', len(key1))
buf += key1
buf += struct.pack('<I', 9)         # STRING
buf += struct.pack('<Q', len(val1))
buf += val1

# Pad to 32-byte alignment
while len(buf) % 32 != 0:
    buf += b'\x00'

with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 7. gguf_invalid_magic.gguf ----------
echo "  gguf_invalid_magic.gguf"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'gguf_invalid_magic.gguf')
with open(out, 'wb') as f:
    f.write(b'NOTGGUF\x00\x00\x00\x00' + b'\x00' * 100)
PY

# ---------- 8. gguf_oversized_string.gguf ----------
echo "  gguf_oversized_string.gguf"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'gguf_oversized_string.gguf')
buf = bytearray()
buf += b'GGUF'
buf += struct.pack('<I', 3)
buf += struct.pack('<Q', 0)         # tensor_count = 0
buf += struct.pack('<Q', 1)         # metadata_kv_count = 1

# Key str + val claims a 2 MiB string (larger than 1 MiB limit), but store shorter
key1 = b'huge_key'
val1 = b'SHORT_VAL'
buf += struct.pack('<Q', len(key1))
buf += key1
buf += struct.pack('<I', 9)          # STRING
buf += struct.pack('<Q', 2 * 1024 * 1024)  # claims 2 MiB, actual data is shorter
buf += val1
buf += b'\x00' * 64

with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 9. gguf_excessive_kv_count.gguf ----------
echo "  gguf_excessive_kv_count.gguf"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'gguf_excessive_kv_count.gguf')
buf = bytearray()
buf += b'GGUF'
buf += struct.pack('<I', 3)
buf += struct.pack('<Q', 0)          # tensor_count = 0
buf += struct.pack('<Q', 2_000_000)  # excessive KV count
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

# ---------- 10. onnx_minimal.bin ----------
echo "  onnx_minimal.bin"
python3 - <<PY
import os

def wire_varint(v):
    buf = bytearray()
    while v > 0x7F:
        buf.append((v & 0x7F) | 0x80)
        v >>= 7
    buf.append(v & 0x7F)
    return bytes(buf)

def wire_field(field_num, wire_type, payload):
    return wire_varint((field_num << 3) | wire_type) + payload

def wire_len_delimited(field_num, data):
    payload = wire_varint(len(data)) + data
    return wire_field(field_num, 2, payload)

def wire_string(field_num, s):
    return wire_len_delimited(field_num, s.encode('utf-8'))

def wire_embedded(field_num, msg_bytes):
    return wire_len_delimited(field_num, msg_bytes)

# ValueInfoProto: name=1 (string)
def make_value_info(name):
    return wire_string(1, name)

# NodeProto: name=3, op_type=4, input=1, output=2
def make_node(name, op_type, inputs, outputs):
    body = b''
    for inp in inputs:
        body += wire_string(1, inp)
    for outp in outputs:
        body += wire_string(2, outp)
    body += wire_string(3, name)
    body += wire_string(4, op_type)
    return wire_embedded(2, body)

# GraphProto: name=1, node=2, input=4, output=5
graph = b''
graph += wire_string(1, 'main_graph')
graph += make_node('relu', 'Relu', ['input'], ['output'])
graph += wire_embedded(4, make_value_info('input'))
graph += wire_embedded(5, make_value_info('output'))
graph_bytes = wire_embedded(10, graph)

# Metadata property entry: key=1, value=2
meta_entry = wire_string(1, 'framework') + wire_string(2, 'onnx')
meta_bytes = wire_len_delimited(14, meta_entry)

# OperatorSetIdProto: domain=1, version=2
opset = wire_string(1, '') + wire_field(2, 0, wire_varint(14))
opset_bytes = wire_len_delimited(11, opset)

# ModelProto: ir_version=1, producer_name=7, producer_version=8, domain=9,
#   doc_string=6, metadata_props=14, graph=10
model = b''
model += wire_field(1, 0, wire_varint(8))   # ir_version = 8
model += wire_string(7, 'test-producer')
model += wire_string(8, '1.0.0')
model += wire_string(9, 'ai.test')
model += wire_string(6, 'test ONNX model')
model += meta_bytes
model += opset_bytes
model += graph_bytes

out = os.path.join('$CORPUS_DIR', 'onnx_minimal.bin')
with open(out, 'wb') as f:
    f.write(model)
PY

# ---------- 11. onnx_with_tensor_data.bin ----------
echo "  onnx_with_tensor_data.bin"
python3 - <<PY
import os

def wire_varint(v):
    buf = bytearray()
    while v > 0x7F:
        buf.append((v & 0x7F) | 0x80)
        v >>= 7
    buf.append(v & 0x7F)
    return bytes(buf)

def wire_field(field_num, wire_type, payload):
    return wire_varint((field_num << 3) | wire_type) + payload

def wire_len_delimited(field_num, data):
    payload = wire_varint(len(data)) + data
    return wire_field(field_num, 2, payload)

def wire_string(field_num, s):
    return wire_len_delimited(field_num, s.encode('utf-8'))

def wire_embedded(field_num, msg_bytes):
    return wire_len_delimited(field_num, msg_bytes)

# GraphProto with initializer containing raw_data
dims = wire_field(1, 0, wire_varint(4))
data_type = wire_field(2, 0, wire_varint(1))

# raw_data with canary
canary = b'SECRET_TENSOR_DATA_SHOULD_NOT_BE_EXTRACTED'
raw_data = wire_len_delimited(9, canary)

initializer_body = dims + data_type + raw_data
initializer = wire_len_delimited(6, initializer_body)

graph = wire_string(1, 'graph') + initializer
graph_bytes = wire_embedded(10, graph)

model = wire_field(1, 0, wire_varint(8)) + wire_string(7, 'prod') + graph_bytes

out = os.path.join('$CORPUS_DIR', 'onnx_with_tensor_data.bin')
with open(out, 'wb') as f:
    f.write(model)
PY

# ---------- 12. onnx_truncated.bin ----------
echo "  onnx_truncated.bin"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'onnx_truncated.bin')
with open(out, 'wb') as f:
    f.write(b'\x08\x08\x32\xFF')
PY

# ---------- 13. pickle_protocol_2.pkl ----------
echo "  pickle_protocol_2.pkl"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'pickle_protocol_2.pkl')
buf = b'\x80\x02' + b'}Hello World{'
with open(out, 'wb') as f:
    f.write(buf)
PY

# ---------- 14. pickle_protocol_5.pkl ----------
echo "  pickle_protocol_5.pkl"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'pickle_protocol_5.pkl')
buf = b'\x80\x05' + b'\x95\x10\x00\x00\x00\x00\x00\x00\x00' + b'NOT_REAL_PICKLE'
with open(out, 'wb') as f:
    f.write(buf)
PY

# ---------- 15. pytorch_archive.pt ----------
echo "  pytorch_archive.pt"
python3 - <<PY
import struct, zlib, os
out = os.path.join('$CORPUS_DIR', 'pytorch_archive.pt')

def zip_local_file(name, data, crc32_val, comp_method=0):
    buf = bytearray()
    buf += b'PK\x03\x04'
    buf += struct.pack('<H', 20)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', comp_method)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<I', crc32_val)
    buf += struct.pack('<I', len(data))
    buf += struct.pack('<I', len(data))
    fn = name.encode('utf-8')
    buf += struct.pack('<H', len(fn))
    buf += struct.pack('<H', 0)
    buf += fn
    buf += data
    return bytes(buf)

def zip_central_dir(name, crc32_val, offset, comp_size, uncomp_size):
    buf = bytearray()
    buf += b'PK\x01\x02'
    buf += struct.pack('<H', 20)
    buf += struct.pack('<H', 20)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<I', crc32_val)
    buf += struct.pack('<I', comp_size)
    buf += struct.pack('<I', uncomp_size)
    fn = name.encode('utf-8')
    buf += struct.pack('<H', len(fn))
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<I', 0)
    buf += struct.pack('<I', offset)
    buf += fn
    return bytes(buf)

def zip_eocd(entries_count, central_dir_size, central_dir_offset):
    buf = bytearray()
    buf += b'PK\x05\x06'
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', 0)
    buf += struct.pack('<H', entries_count)
    buf += struct.pack('<H', entries_count)
    buf += struct.pack('<I', central_dir_size)
    buf += struct.pack('<I', central_dir_offset)
    buf += struct.pack('<H', 0)
    return bytes(buf)

pickle_data = b'\x80\x02' + b'PT_ZIP_ARCHIVE_MARKER' + b'\x80\x05'
crc = zlib.crc32(pickle_data)

local1 = zip_local_file('archive/data.pkl', pickle_data, crc)
local2 = zip_local_file('archive/version', b'2.0', zlib.crc32(b'2.0'))

all_data = local1 + local2

cd1 = zip_central_dir('archive/data.pkl', crc, 0, len(pickle_data), len(pickle_data))
cd2 = zip_central_dir('archive/version', zlib.crc32(b'2.0'), len(local1), 3, 3)
cd = cd1 + cd2
eocd = zip_eocd(2, len(cd), len(all_data))

with open(out, 'wb') as f:
    f.write(all_data + cd + eocd)
PY

# ---------- 16. empty_file.model ----------
echo "  empty_file.model"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'empty_file.model')
open(out, 'wb').close()
PY

# ---------- 17. adjacent_config_model.json ----------
echo "  adjacent_config_model.json"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'adjacent_config_model.json')
with open(out, 'w') as f:
    f.write('{"architectures":["LlamaForCausalLM"],"hidden_size":768,"num_hidden_layers":12}')
PY

# ---------- 18. adjacent_tokenizer.json ----------
echo "  adjacent_tokenizer.json"
python3 - <<PY
import os
out = os.path.join('$CORPUS_DIR', 'adjacent_tokenizer.json')
with open(out, 'w') as f:
    f.write('{"model":{"type":"BPE","vocab":{"<s>":0,"</s>":1}}}')
PY

# ---------- 19. gguf_oversized_tensor_count.gguf ----------
echo "  gguf_oversized_tensor_count.gguf"
python3 - <<PY
import struct, os
out = os.path.join('$CORPUS_DIR', 'gguf_oversized_tensor_count.gguf')
buf = bytearray()
buf += b'GGUF'
buf += struct.pack('<I', 3)
buf += struct.pack('<Q', 2_000_000)  # excessive tensor count
buf += struct.pack('<Q', 0)
with open(out, 'wb') as f:
    f.write(bytes(buf))
PY

echo "=== Model corpus generation complete ==="
ls -la "$CORPUS_DIR"
