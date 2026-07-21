# Parser Support Matrix

> Auto-generated from parser registry and corpus manifest.
> Manifest version: 1.0, cases: 159

## Format Coverage

| Format | Parser ID | Version | Covered Regions | Uncovered / Partial | Locator | Limits | Corpus Cases |
|--------|-----------|---------|-----------------|---------------------|---------|--------|-------------|
| gzip | gzip | 1.0.0 | GZip single-file decompression. Child discovery. | 0 partial, 4 not covered | VirtualPath!<gzip-content> + SourceStart/SourceLength | Uncompressed size <= declared x 10, 4 GiB/entry | `archives/sample.txt_gz`, `archives/sample_with_name.txt_gz`, `oci/oci-layout/blobs/sha256/048a1c046f8ca614e970d1878028ec2cbf004bdc90cd2099554c39a521fa796d`, `oci/oci-layout/blobs/sha256/38216a202a81fe5d065a9ed5ad5831727cc6b1c8fdc224c5f3c4f95684761867` |
| model | model | 1.0.0 | SafeTensors (header JSON -> metadata), GGUF v2/v3 (KV pairs + tensor shapes -> metadata), ONNX (ir_version, graph, opset -> metadata). Pickle safety gate. | 4 partial, 6 not covered | VirtualPath + SourceStart/SourceLength (metadata only) | Pickle detection (dangerous rejection), SafeTensors header parse, GGUF walk, ONNX protobuf walk | `models/gguf_v2_minimal_gguf`, `models/gguf_v3_minimal_gguf`, `models/pickle_protocol_5_pkl`, `models/safetensors_minimal_safetensors`, `models/gguf_excessive_kv_count_gguf`, ... (+5) |
| openxml | openxml | 1.0.0 | DOCX (paragraphs, tables, headers, footers), XLSX (sheets, cells), PPTX (slides, notes). Metadata + VBA scanning. | 2 partial, 3 not covered | VirtualPath!part/paragraph/sheet/slide + SourceStart/SourceLength | OLE CFB detection, encrypted detection, 512 KiB chunks | `office/external_rel_docx`, `office/sample_docx`, `office/sample_pptx`, `office/sample_xlsx`, `office/sample_docm`, ... (+4) |
| pdf | pdf | 1.0.0 | Page text extraction, metadata, annotations, form fields, bookmarks, attachments. PdfPig v0.1.14. | 2 partial, 1 not covered | Page + BlockIndex + SourceStart/SourceLength | 10 MiB text/page, 1M letters/page, encrypted detection, <=64 MiB attachments | `pdf/annotations_forms_pdf`, `pdf/huge_stream_pdf`, `pdf/malformed_xref_pdf`, `pdf/recursive_page_tree_pdf`, `pdf/sample_pdf`, ... (+4) |
| tar | tar | 1.0.0 | TAR entries (regular, directory, symlink, hardlink). Child discovery. | 1 partial, 3 not covered | VirtualPath!entry + SourceStart/SourceLength | 100k entries, depth 5, 4 GiB/entry, 50 GiB total | `archives/symlink_tar`, `archives/simple_tar`, `archives/sparse_huge_tar_tar`, `archives/valid_tar_tar` |
| text | text | 1.0.0 | Plain text with encoding detection (UTF-8, UTF-16, GB18030). Heuristic binary classification. | 0 partial, 1 not covered | SourceStart/SourceLength + VirtualPath | 512 KiB chunks, 1 MiB frame, location-map <=8192 entries | `models/adjacent_config_model_json`, `models/adjacent_tokenizer_json`, `models/onnx_minimal_bin`, `models/onnx_with_tensor_data_bin`, `models/safetensors_with_canary_weights_safetensors`, ... (+68) |
| zip | zip | 1.0.0 | ZIP/JAR/APK/EPUB entries. Path traversal + encryption detection. Child discovery. | 0 partial, 13 not covered | VirtualPath!entry + SourceStart/SourceLength | 100k entries, depth 5, 4 GiB/entry, 50 GiB total | `archives/absolute_path_zip`, `archives/case_collision_zip`, `archives/corrupt_central_dir_zip`, `archives/depth_6_zip`, `archives/duplicate_name_zip`, ... (+8) |

## Unsupported Formats

The following formats have no dedicated parser and produce `UnsupportedFormat` gaps:

- Formats: binary, elf, empty, java_class, pe
- Total cases: 37

## Coverage Summary

| Status | Count |
|--------|-------|
| Covered | 82 |
| Partial | 9 |
| Not Covered | 68 |
| **Total** | **159** |
