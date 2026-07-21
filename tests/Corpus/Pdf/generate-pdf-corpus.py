#!/usr/bin/env python3
"""Generate deterministic PDF corpus for PdfPig parser testing.

Produces PDFs with:
  - Text: ordered/unordered, Chinese font, metadata, annotations,
    form fields, bookmarks, safe attachment
  - Edge: image-only, mixed text+image, encrypted, malformed xref,
    recursive page tree, huge declared stream, truncated tail
"""

import os
import sys
import zlib
import io
from pathlib import Path

OUTPUT_DIR = Path(__file__).resolve().parent


def write_pdf(path: Path, pdf_bytes: bytes):
    path.write_bytes(pdf_bytes)
    print(f"  wrote {path.name} ({len(pdf_bytes)} bytes)")


# ─── PDF primitive helpers ──────────────────────────────────────


def make_obj(num, body):
    """Create a PDF indirect object. body must be bytes."""
    return b"%d 0 obj\n" % num + body + b"\nendobj\n"


def make_stream_obj(num, stream_bytes, extra=b""):
    """Create a PDF stream object."""
    header = (b"%d 0 obj\n<< /Length %d" % (num, len(stream_bytes)) +
              extra + b" >>\nstream\n")
    return header + stream_bytes + b"\nendstream\nendobj\n"


def make_info(num, title=b"", author=b"", subject=b"",
              keywords=b"", creator=b"", producer=b""):
    entries = []
    if title:
        entries.append(b"/Title " + title)
    if author:
        entries.append(b"/Author " + author)
    if subject:
        entries.append(b"/Subject " + subject)
    if keywords:
        entries.append(b"/Keywords " + keywords)
    if creator:
        entries.append(b"/Creator " + creator)
    if producer:
        entries.append(b"/Producer " + producer)
    return make_obj(num, b"<< " + b" ".join(entries) + b" >>")


def pdf_literal_string(s):
    """Encode a string as a PDF literal string (with BOM for UTF-16BE)."""
    # Use UTF-16BE with BOM for Unicode
    encoded = b"\xfe\xff" + s.encode("utf-16-be")
    return b"(" + _escape_pdf_bytes(encoded) + b")"


def _escape_pdf_bytes(b):
    """Escape special characters for PDF literal strings."""
    result = bytearray()
    for byte in b:
        if byte == 0x28:  # (
            result.extend(b"\\(")
        elif byte == 0x29:  # )
            result.extend(b"\\)")
        elif byte == 0x5C:  # \
            result.extend(b"\\\\")
        elif byte == 0x0D:  # CR
            result.extend(b"\\r")
        else:
            result.append(byte)
    return bytes(result)


def text_content_stream(text, font_name=b"F1", font_size=12):
    """Minimal text content stream using Tj operator."""
    ops = [
        b"BT",
        b"/" + font_name + b" %d Tf" % font_size,
        b"72 700 Td",
    ]
    y = 700
    for line in text.split("\n"):
        esc = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        ops.append(b"(%s) Tj" % esc.encode("ascii", errors="replace"))
        y -= 15
        ops.append(b"72 %d Td" % y)

    ops.append(b"ET")
    return b" ".join(ops)


def make_type1_font(num, base_font=b"Helvetica"):
    return make_obj(num, b"<< /Type /Font /Subtype /Type1 /BaseFont /" + base_font + b" >>")


def make_page(num, contents_ref, resources_ref, parent_ref,
              media_box=b"[0 0 612 792]", extra=b""):
    return make_obj(num, (
        b"<< /Type /Page /Parent %d 0 R " % parent_ref +
        b"/MediaBox " + media_box + b" " +
        b"/Resources %d 0 R " % resources_ref +
        b"/Contents %d 0 R" % contents_ref +
        extra + b" >>"
    ))


def make_pages(num, kids, count=1):
    kid_refs = b" ".join(b"%d 0 R" % k for k in kids)
    return make_obj(num, b"<< /Type /Pages /Kids [" + kid_refs + b"] /Count %d >>" % count)


def make_catalog(num, pages_ref, **extra):
    entries = [b"/Type /Catalog", b"/Pages %d 0 R" % pages_ref]
    for k_bytes, v_bytes in extra.items():
        entries.append(b"/%b %b" % (k_bytes, v_bytes))
    return make_obj(num, b"<< " + b" ".join(entries) + b" >>")


def make_xref(offsets):
    """Build cross-reference table."""
    parts = [b"xref"]
    parts.append(b"0 %d" % (len(offsets) + 1))
    parts.append(b"0000000000 65535 f ")
    for off in offsets:
        parts.append(b"%010d 00000 n " % off)
    return b"\n".join(parts)


def build_pdf(objects, catalog_ref, info_ref=0, trailer_extra=b""):
    """Assemble objects into a complete PDF."""
    body_parts = [b"%PDF-1.7", b"%\xe2\xe3\xcf\xd3"]
    offset = len(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")

    offsets = []
    for obj in objects:
        offsets.append(offset)
        body_parts.append(obj)
        offset += len(obj) + 1

    xref_offset = offset + 1
    xref = make_xref(offsets)

    trailer_entries = [
        b"/Size %d" % (len(objects) + 1),
        b"/Root %d 0 R" % catalog_ref,
    ]
    if info_ref > 0:
        trailer_entries.append(b"/Info %d 0 R" % info_ref)
    trailer_entries.append(trailer_extra)
    trailer = b"trailer\n<< " + b" ".join(trailer_entries) + b" >>\n"

    end = b"startxref\n" + str(xref_offset).encode("ascii") + b"\n%%EOF"

    return b"\n".join(body_parts + [xref, trailer, end])


# ─── Minimal JPEG ───────────────────────────────────────────────


def make_minimal_jpeg():
    """Smallest valid JPEG (1x1 gray pixel)."""
    tables = bytes([
        0xFF, 0xD8,  # SOI
        0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,  # APP0 JFIF
        0xFF, 0xDB, 0x00, 0x43, 0x00,  # DQT
    ] + [8] * 64 + [
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01,
        0x01, 0x01, 0x11, 0x00,  # SOF0
        0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x05, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,  # DHT
        0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,  # SOS
        0x7F, 0xAA,  # Compressed data
        0xFF, 0xD9,  # EOI
    ])
    return tables


# ─── PDF generators ─────────────────────────────────────────────


def generate_sample_pdf():
    """PDF with Chinese metadata, text content, annotations, form field,
    bookmark, and safe attachment."""
    # Object layout:
    # 1: catalog, 2: pages, 3: page, 4: content, 5: resources,
    # 6: font, 7: outline, 8: outline item, 9: info
    # 10: names, 11: embedded files dict, 12: file spec, 13: file stream
    # 14: annot, 15: acroform, 16: form field

    content_text = (
        "Hello World from PDF\n"
        "This is page one with multiple lines.\n"
        "Line three is here for coverage.\n"
    )
    content_stream = text_content_stream(content_text)
    content_obj = make_stream_obj(4, content_stream)

    font = make_type1_font(6, b"Helvetica")
    resources = make_obj(5, b"<< /Font << /F1 6 0 R >> /ProcSet [/PDF /Text] >>")

    # Annotation (link with content text)
    annot = make_obj(10, (
        b"<< /Type /Annot /Subtype /Link /Rect [72 600 200 615] "
        b"/Border [0 0 0] /Contents (Click here for more info) >>"
    ))

    # Form field (AcroForm)
    form_field = make_obj(12, (
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (name_field) "
        b"/V (Hello) /Rect [72 500 200 520] /F 4 >>"
    ))
    acroform = make_obj(11, b"<< /Fields [12 0 R] /NeedAppearances true >>")

    # Page with annotations
    page = make_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 5 0 R /Contents 4 0 R /Annots [10 0 R] >>")

    pages = make_pages(2, [3], 1)

    # Bookmark
    outline_item = make_obj(8, (
        b"<< /Title (Chapter 1) /Parent 7 0 R /Dest [3 0 R /Fit] >>"
    ))
    outline = make_obj(7, (
        b"<< /Type /Outlines /First 8 0 R /Last 8 0 R /Count 1 >>"
    ))

    # Info with metadata
    info = make_info(9,
        title=pdf_literal_string("你好世界"),
        author=pdf_literal_string("中国人"),
        subject=b"(PDF Test Document)",
        keywords=b"(test corpus pdf)",
        creator=b"(SecurityReview Corpus Generator)",
        producer=b"(Python pypdf)")

    # Embedded file (attachment)
    attach_data = b"This is a safe text attachment.\nIt has two lines.\n"
    file_stream = make_stream_obj(14, attach_data,
        b" /Type /EmbeddedFile /Subtype /text#2Fplain")
    file_spec = make_obj(13, (
        b"<< /Type /Filespec /F (safe_attachment.txt) "
        b"/UF (safe_attachment.txt) /EF << /F 14 0 R >> >>"
    ))
    ef_names = make_obj(15, b"<< /Names [(safe_attachment.txt) 13 0 R] >>")
    ef_dict = make_obj(16, b"<< /Names 15 0 R >>")

    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R "
        b"/Outlines 7 0 R /AcroForm 11 0 R "
        b"/Names << /EmbeddedFiles 16 0 R >> >>")

    objects = [
        catalog, pages, page, content_obj, resources, font,
        outline, outline_item, info,
        annot, acroform, form_field,
        file_spec, file_stream, ef_names, ef_dict,
    ]

    return build_pdf(objects, 1, info_ref=9)


def generate_image_only_pdf():
    """PDF with a single page containing only an image (no text)."""
    jpeg = make_minimal_jpeg()

    # Objects: 1 catalog, 2 pages, 3 page, 4 content, 5 resources, 6 img, 7 font (unused)
    img = make_stream_obj(6, jpeg,
        b" /Type /XObject /Subtype /Image /Width 1 /Height 1 "
        b"/ColorSpace /DeviceGray /BitsPerComponent 8")

    resources = make_obj(5,
        b"<< /XObject << /Im0 6 0 R >> /ProcSet [/PDF /ImageB] >>")

    content = b"q 612 0 0 792 0 0 cm /Im0 Do Q"
    content_obj = make_stream_obj(4, content)

    page = make_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 5 0 R /Contents 4 0 R >>")
    pages = make_pages(2, [3], 1)
    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")

    return build_pdf([catalog, pages, page, content_obj, resources, img], 1)


def generate_mixed_pdf():
    """PDF with a page containing both text and an image."""
    jpeg = make_minimal_jpeg()

    img = make_stream_obj(6, jpeg,
        b" /Type /XObject /Subtype /Image /Width 1 /Height 1 "
        b"/ColorSpace /DeviceGray /BitsPerComponent 8")

    font = make_type1_font(7, b"Helvetica")
    resources = make_obj(5,
        b"<< /Font << /F1 7 0 R >> /XObject << /Im0 6 0 R >> "
        b"/ProcSet [/PDF /Text /ImageB] >>")

    content = (
        b"BT /F1 12 Tf 72 700 Td (Some text content) Tj ET "
        b"q 100 0 0 100 200 400 cm /Im0 Do Q"
    )
    content_obj = make_stream_obj(4, content)

    page = make_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 5 0 R /Contents 4 0 R >>")
    pages = make_pages(2, [3], 1)
    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")

    return build_pdf([catalog, pages, page, content_obj, resources, img, font], 1)


def generate_encrypted_pdf():
    """PDF encrypted using pypdf with standard encryption."""
    try:
        from pypdf import PdfWriter, PdfReader

        # Build a minimal text PDF
        inner = generate_minimal_text_pdf(b"Confidential document content.")
        buf = io.BytesIO(inner)
        reader = PdfReader(buf)
        writer = PdfWriter(clone_from=reader)
        writer.encrypt("secret", "secret")
        buf2 = io.BytesIO()
        writer.write(buf2)
        return buf2.getvalue()
    except Exception as e:
        # Fallback: create a PDF with Encrypt dictionary
        print(f"  Note: pypdf encrypt failed ({e}), generating placeholder")
        inner = generate_minimal_text_pdf(b"Encrypted content placeholder.")
        # Insert an /Encrypt entry in trailer
        idx = inner.rfind(b"trailer")
        if idx >= 0:
            inner = (inner[:idx + 7] +
                     b"\n<< /Encrypt << /Filter /Standard /V 2 /R 3 /Length 128 /O <00000000000000000000000000000000000000000000000000000000000000000000> /U <00000000000000000000000000000000000000000000000000000000000000000000> /P -1060 >> >>\n" +
                     inner[idx + 7:])
        return inner


def generate_minimal_text_pdf(text):
    """Helper: minimal single-page PDF with given text."""
    content = text_content_stream(text.decode("ascii", errors="replace"))
    content_obj = make_stream_obj(4, content)
    font = make_type1_font(5, b"Helvetica")
    resources = make_obj(6, b"<< /Font << /F1 5 0 R >> /ProcSet [/PDF /Text] >>")
    page = make_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 6 0 R /Contents 4 0 R >>")
    pages = make_pages(2, [3], 1)
    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    return build_pdf([catalog, pages, page, content_obj, font, resources], 1)


def generate_malformed_xref_pdf():
    """PDF with intentionally malformed cross-reference offsets."""
    inner = generate_minimal_text_pdf(b"PDF with malformed xref table.")
    idx = inner.find(b"xref\n")
    if idx >= 0:
        start = inner.find(b"\n", idx) + 1
        corrupted = bytearray(inner)
        n_pos = corrupted.find(b" 00000 n ", start)
        if n_pos > 0:
            corrupted[n_pos - 15:n_pos - 5] = b"9999999999"
        inner = bytes(corrupted)
    return inner


def generate_recursive_page_tree_pdf():
    """PDF with a pages node that references itself (recursive)."""
    content = text_content_stream("Test page with recursive tree.")
    content_obj = make_stream_obj(6, content)
    font = make_type1_font(7, b"Helvetica")
    resources = make_obj(5, b"<< /Font << /F1 7 0 R >> /ProcSet [/PDF /Text] >>")
    page = make_obj(4,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 5 0 R /Contents 6 0 R >>")
    # Pages 2 includes itself in Kids
    pages = make_obj(2, b"<< /Type /Pages /Kids [2 0 R 4 0 R] /Count 2 >>")
    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    return build_pdf([catalog, pages, make_obj(3, b"<< >>"),
                       page, resources, content_obj, font], 1)


def generate_huge_stream_pdf():
    """PDF with a stream declaring huge length but small actual data."""
    huge_len = 100 * 1024 * 1024
    stream_data = b"small data"
    header = b"6 0 obj\n<< /Length %d >>\nstream\n" % huge_len

    font = make_type1_font(7, b"Helvetica")
    resources = make_obj(5,
        b"<< /Font << /F1 7 0 R >> /ProcSet [/PDF /Text] >>")
    content_obj = make_stream_obj(4,
        b"BT /F1 12 Tf 72 700 Td (some text) Tj ET")
    page = make_obj(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 5 0 R /Contents 4 0 R >>")
    pages = make_pages(2, [3], 1)
    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R >>")

    objects = [
        catalog, pages, page, content_obj, resources,
        header + stream_data + b"\nendstream\nendobj\n", font,
    ]
    return build_pdf(objects, 1)


def generate_truncated_pdf():
    """PDF truncated before %%EOF."""
    inner = generate_minimal_text_pdf(b"PDF to be truncated.")
    idx = inner.rfind(b"%%EOF")
    if idx >= 0:
        return inner[:idx]
    return inner[:len(inner) // 2]


def generate_annotations_forms_pdf():
    """PDF with annotations, form fields, and bookmarks."""
    content = text_content_stream("Page with annotations and forms.")
    content_obj = make_stream_obj(4, content)
    font = make_type1_font(5, b"Helvetica")
    resources = make_obj(6,
        b"<< /Font << /F1 5 0 R >> /ProcSet [/PDF /Text] >>")

    annot = make_obj(7, (
        b"<< /Type /Annot /Subtype /Link /Rect [72 600 200 615] "
        b"/Border [0 0 0] /Contents (Click here for more info) "
        b"/A << /Type /Action /S /URI /URI (https://example.com) >> >>"
    ))

    page = make_obj(3, (
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources 6 0 R /Contents 4 0 R /Annots [7 0 R] >>"
    ))
    pages = make_pages(2, [3], 1)

    form_field = make_obj(9, (
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (name_field) "
        b"/V (Hello) /Rect [72 500 200 520] /F 4 >>"
    ))
    acroform = make_obj(8, b"<< /Fields [9 0 R] /NeedAppearances true >>")

    outline_item = make_obj(11, (
        b"<< /Title (Section A) /Parent 10 0 R /Dest [3 0 R /Fit] >>"
    ))
    outline = make_obj(10, (
        b"<< /Type /Outlines /First 11 0 R /Last 11 0 R /Count 1 >>"
    ))

    catalog = make_obj(1, b"<< /Type /Catalog /Pages 2 0 R "
        b"/Outlines 10 0 R /AcroForm 8 0 R >>")

    objects = [
        catalog, pages, page, content_obj, font, resources,
        annot, acroform, form_field, outline, outline_item,
    ]
    return build_pdf(objects, 1)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Generating PDF corpus...")

    generators = {
        "sample.pdf": generate_sample_pdf,
        "image_only.pdf": generate_image_only_pdf,
        "mixed.pdf": generate_mixed_pdf,
        "encrypted.pdf": generate_encrypted_pdf,
        "malformed_xref.pdf": generate_malformed_xref_pdf,
        "recursive_page_tree.pdf": generate_recursive_page_tree_pdf,
        "huge_stream.pdf": generate_huge_stream_pdf,
        "truncated.pdf": generate_truncated_pdf,
        "annotations_forms.pdf": generate_annotations_forms_pdf,
    }

    for filename, gen_fn in generators.items():
        try:
            pdf_bytes = gen_fn()
            write_pdf(OUTPUT_DIR / filename, pdf_bytes)
        except Exception as e:
            import traceback
            print(f"  ERROR generating {filename}: {e}", file=sys.stderr)
            traceback.print_exc()

    print(f"\nCorpus complete in {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
