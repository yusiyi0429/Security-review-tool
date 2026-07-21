#!/usr/bin/env python3
"""Generate synthetic OCI image layout and Docker-save TAR fixtures without Docker."""

import hashlib
import json
import os
import shutil
import struct
import sys
import tarfile
import time
import gzip
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent

def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()

def create_tar_entry_bytes(name: str, data: bytes, mode=0o644) -> bytes:
    """Create a minimal ustar-format tar entry. Only for files that fit in one block."""
    MAX_PATH = 100
    MAX_LINK = 100
    if len(name) > MAX_PATH or isinstance(data, str):
        raise ValueError(f"name too long or data not bytes: {name}")

    header = bytearray(512)
    def put_str(b, offset, s, maxlen):
        enc = s.encode("utf-8")[:maxlen-1]
        b[offset:offset+len(enc)] = enc

    put_str(header, 0, name, 100)           # name
    mode_str = f"{mode:07o}\0"
    header[100:108] = mode_str.encode()
    uid_str = "0000000\0"
    header[108:116] = uid_str.encode()
    gid_str = "0000000\0"
    header[116:124] = gid_str.encode()
    size_str = f"{len(data):011o}\0"
    header[124:136] = size_str.encode()
    mtime_str = f"{int(time.time()):011o}\0"
    header[136:148] = mtime_str.encode()
    # typeflag = '0' (regular)
    header[156] = ord('0')
    put_str(header, 257, "root", 32)
    put_str(header, 297, "root", 32)

    # Calculate and store checksum
    for i in range(148, 156):
        header[i] = 32  # blank checksum

    checksum = sum(header)
    checksum_str = f"{checksum:06o}\0 "
    header[148:156] = checksum_str.encode()

    result = bytes(header) + data
    # Pad to 512-byte boundary
    if len(result) % 512 != 0:
        result += b'\0' * (512 - len(result) % 512)
    return result

def create_tar_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    """Create a tar from (name, data_bytes) pairs."""
    parts = []
    for name, data in entries:
        parts.append(create_tar_entry_bytes(name, data))
    # Two zero blocks at end
    parts.append(b'\0' * 1024)
    return b"".join(parts)

def main():
    # ---- Layout ----
    oci_dir = OUT / "oci-layout"
    docker_dir = OUT / "docker-save"

    shutil.rmtree(oci_dir, ignore_errors=True)
    shutil.rmtree(docker_dir, ignore_errors=True)
    oci_dir.mkdir(parents=True, exist_ok=True)
    docker_dir.mkdir(parents=True, exist_ok=True)

    # ---- Layer content ----
    # Layer 1: has a canary file that layer 2 will whiteout
    layer1_files = [
        ("canary.txt", b"This file should be deleted by layer 2\n"),
        ("keep-me.txt", b"This file persists\n"),
        ("bin/app", b"#!/bin/sh\necho hello\n"),
    ]
    layer1_tar = create_tar_bytes(layer1_files)
    layer1_gzip = gzip.compress(layer1_tar)

    # Layer 2: whiteout for canary.txt, opaque whiteout for a dir, plus a new file
    layer2_files = [
        (".wh.canary.txt", b""),         # individual whiteout
        (".wh..wh..opq", b""),           # opaque whiteout marker
        ("new-file.txt", b"added in layer 2\n"),
        ("keep-me.txt", b"updated content\n"),  # overwrite
        ("dir/symlink-file", b"symlink-target-content"),  # symlink target text scanned
        ("dir/hardlink-file", b"hl-target"),               # hardlink target text scanned
    ]
    layer2_tar = create_tar_bytes(layer2_files)
    layer2_gzip = gzip.compress(layer2_tar)

    # ---- Config JSON ----
    config_json = json.dumps({
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": [
                sha256_digest(layer1_tar),
                sha256_digest(layer2_tar),
            ]
        },
        "config": {
            "Env": [
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "NODE_VERSION=20.0.0",
            ],
            "Labels": {
                "org.opencontainers.image.title": "test-image",
                "com.example.vendor": "SecurityReview",
            },
            "Entrypoint": ["/bin/sh", "-c"],
            "Cmd": ["echo", "hello"],
            "WorkingDir": "/app",
            "User": "1000:1000",
            "ExposedPorts": {"8080/tcp": {}},
            "Volumes": {"/data": {}},
        },
        "history": [
            {"created": "2025-01-01T00:00:00Z", "created_by": "FROM alpine:3.19"},
            {"created": "2025-01-01T00:01:00Z", "created_by": "RUN apk add nodejs"},
            {"created": "2025-01-01T00:02:00Z", "created_by": "COPY . /app"},
            {"created": "2025-01-01T00:03:00Z", "created_by": "CMD [\"echo\", \"hello\"]"},
        ]
    }, indent=2).encode("utf-8")
    config_digest = sha256_digest(config_json)
    config_size = len(config_json)

    # ---- Manifest JSON ----
    manifest_json = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer1_gzip),
                "digest": sha256_digest(layer1_gzip),
            },
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer2_gzip),
                "digest": sha256_digest(layer2_gzip),
            },
        ]
    }, indent=2).encode("utf-8")
    manifest_digest = sha256_digest(manifest_json)
    manifest_size = len(manifest_json)

    # ---- Index JSON (multi-platform) ----
    index_json = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": manifest_size,
                "digest": manifest_digest,
                "platform": {
                    "architecture": "amd64",
                    "os": "linux",
                }
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": manifest_size,
                "digest": manifest_digest,
                "platform": {
                    "architecture": "arm64",
                    "os": "linux",
                }
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": 9999,
                "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "platform": {
                    "architecture": "riscv64",
                    "os": "linux",
                },
                "annotations": {
                    "org.opencontainers.image.ref.name": "missing-blob"
                }
            },
        ]
    }, indent=2).encode("utf-8")
    index_size = len(index_json)

    # ---- oci-layout file ----
    oci_layout_content = json.dumps({"imageLayoutVersion": "1.0.0"}).encode("utf-8")

    # ==== OCI Directory Layout ====
    oci_blobs_dir = oci_dir / "blobs" / "sha256"
    oci_blobs_dir.mkdir(parents=True, exist_ok=True)

    (oci_dir / "oci-layout").write_bytes(oci_layout_content)
    (oci_dir / "index.json").write_bytes(index_json)

    def write_blob(digest: str, data: bytes):
        hex_part = digest.removeprefix("sha256:")
        path = oci_blobs_dir / hex_part
        path.write_bytes(data)
        return path

    write_blob(config_digest, config_json)
    write_blob(manifest_digest, manifest_json)
    write_blob(sha256_digest(layer1_gzip), layer1_gzip)
    write_blob(sha256_digest(layer2_gzip), layer2_gzip)

    # ---- Corrupt blob (mismatched size) ----
    corrupt_blob_digest = "sha256:" + "a" * 64
    corrupt_blob_path = oci_blobs_dir / ("a" * 64)
    corrupt_blob_path.write_bytes(b"this is corrupt data with wrong size")

    # ---- Metadata-only manifest referencing corrupt blob ----
    corrupt_manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": len(b"corrupt config"),
            "digest": corrupt_blob_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": len(b"corrupt layer"),
                "digest": corrupt_blob_digest,
            }
        ]
    }, indent=2).encode("utf-8")
    corrupt_manifest_digest = sha256_digest(corrupt_manifest)
    write_blob(corrupt_manifest_digest, corrupt_manifest)

    # ---- Corrupt index referencing corrupt manifest ----
    corrupt_index = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "size": len(corrupt_manifest),
                "digest": corrupt_manifest_digest,
                "platform": {"architecture": "amd64", "os": "linux"}
            }
        ]
    }, indent=2).encode("utf-8")
    (oci_dir / "corrupt-index.json").write_bytes(corrupt_index)

    # ==== Docker-save TAR ====
    # Docker save format: a TAR containing:
    # - manifest.json (array of [{Config, RepoTags, Layers}])
    # - <config_digest_hex>.json (config blob)
    # - <layer_digest_hex>/layer.tar (layer content dirs)
    config_hex = config_digest.removeprefix("sha256:")
    layer1_hex = sha256_digest(layer1_gzip).removeprefix("sha256:")
    layer2_hex = sha256_digest(layer2_gzip).removeprefix("sha256:")

    docker_manifest = json.dumps([{
        "Config": f"{config_hex}.json",
        "RepoTags": ["test-image:latest"],
        "Layers": [
            f"{layer1_hex}/layer.tar",
            f"{layer2_hex}/layer.tar",
        ]
    }]).encode("utf-8")

    docker_tar_entries = [
        ("manifest.json", docker_manifest),
        (f"{config_hex}.json", config_json),
        (f"{layer1_hex}/layer.tar", layer1_gzip),
        (f"{layer2_hex}/layer.tar", layer2_gzip),
    ]
    docker_tar_bytes = create_tar_bytes(docker_tar_entries)

    docker_tar_path = docker_dir / "test-image.tar"
    docker_tar_path.write_bytes(docker_tar_bytes)

    # ---- Golden expectations JSON for tests ----
    golden = {
        "config_digest": config_digest,
        "config_size": config_size,
        "manifest_digest": manifest_digest,
        "manifest_size": manifest_size,
        "layer1_digest": sha256_digest(layer1_gzip),
        "layer1_size": len(layer1_gzip),
        "layer1_diff_id": sha256_digest(layer1_tar),
        "layer1_files": [n for n, _ in layer1_files],
        "layer2_digest": sha256_digest(layer2_gzip),
        "layer2_size": len(layer2_gzip),
        "layer2_diff_id": sha256_digest(layer2_tar),
        "layer2_files": [n for n, _ in layer2_files],
        "oci_layout_version": "1.0.0",
        "index_size": index_size,
        "oci_manifest_count": 3,
        "docker_repo_tags": ["test-image:latest"],
        "docker_layers_count": 2,
    }
    (OUT / "oci-golden.json").write_text(json.dumps(golden, indent=2))

    print(f"Generated corpus at {OUT}")
    print(f"  OCI layout: {oci_dir}")
    print(f"  Docker TAR: {docker_tar_path} ({docker_tar_path.stat().st_size} bytes)")
    print(f"  Golden JSON: {OUT / 'oci-golden.json'}")

if __name__ == "__main__":
    main()
