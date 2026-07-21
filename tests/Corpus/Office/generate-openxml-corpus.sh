#!/usr/bin/env bash
# generate-openxml-corpus.sh
# Generates deterministic OpenXML golden fixtures for OpenXmlParserTests.
# Output: tests/Corpus/Office/
#
# Requires python3 with python-docx, openpyxl, python-pptx.
# Use the repo-local venv: .venv-corpus/bin/python

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
PYTHON="$REPO_ROOT/.venv-corpus/bin/python"

rm -rf "$CORPUS_DIR"/*.docx "$CORPUS_DIR"/*.xlsx "$CORPUS_DIR"/*.pptx \
       "$CORPUS_DIR"/*.docm "$CORPUS_DIR"/*.xlsm "$CORPUS_DIR"/*.pptm \
       "$CORPUS_DIR"/*.doc "$CORPUS_DIR"/*.xls "$CORPUS_DIR"/*.ppt

echo "=== Generating OpenXML corpus in $CORPUS_DIR ==="

# ---------- Helper: run python snippet ----------
run_py() {
    "$PYTHON" -c "$1"
}

# ================================================================
# 1. sample.docx — Word with all content types
# ================================================================
echo "  sample.docx"
run_py "
import docx
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.opc.constants import RELATIONSHIP_TYPE as RT
import datetime

doc = Document()

# Core properties
doc.core_properties.title = 'Sample Document Title'
doc.core_properties.author = 'Test Author'
doc.core_properties.subject = 'Security Review Test'
doc.core_properties.keywords = 'canary, test, security'
doc.core_properties.comments = 'A sample document for parser testing'
doc.core_properties.last_modified_by = 'Test Editor'

# Body text
doc.add_heading('Sample Document', level=1)
p = doc.add_paragraph('This is the first paragraph with a canary token: ')
p.add_run('tok_docx_main_p1_r1').bold = True
p = doc.add_paragraph('Second paragraph with more text content.')
p.add_run(' tok_docx_main_p2_r1').italic = True

# Header
section = doc.sections[0]
header = section.header
header.is_linked_to_previous = False
hp = header.paragraphs[0]
hp.text = 'Header Canary: tok_docx_header_h1'

# Footer
footer = section.footer
footer.is_linked_to_previous = False
fp = footer.paragraphs[0]
fp.text = 'Footer Canary: tok_docx_footer_f1'

# Comment canary text
p_comment = doc.add_paragraph()
p_comment.add_run('tok_docx_comment_text')

# Footnote - we need to add via XML
# For simplicity, we add recognizable text for footnotes/endnotes
# These are added via the footnotes part
footnotes_part = doc.part.element.makeelement(qn('w:footnotes'), {})
# We'll handle this at the ZIP level

# Endnote placeholder text
doc.add_paragraph('Endnote canary: tok_docx_endnote_e1')

# Glossary/document.xml - not easily added via python-docx, handle at ZIP level
doc.add_paragraph('Glossary canary: tok_docx_glossary')

# Custom XML
custom_xml_text = '<customData>tok_docx_customxml_data</customData>'
# Inject via lxml if possible
doc.add_paragraph('Custom XML canary: tok_docx_customxml')

# Save
doc.save('$CORPUS_DIR/sample.docx')
print('  sample.docx saved')
"

# Post-process sample.docx: add footnotes, endnotes, glossary, custom XML via ZIP manipulation
echo "  post-processing sample.docx (footnotes, endnotes, glossary, custom XML)..."
run_py "
import zipfile, io, os, shutil

src = '$CORPUS_DIR/sample.docx'
tmp = src + '.tmp'

# Read existing ZIP
with zipfile.ZipFile(src, 'r') as zin:
    # Find the [Content_Types].xml
    ct_data = zin.read('[Content_Types].xml')
    
    # Build content_types additions (no Default Extension to avoid duplicates)
    ct_additions = '''
  <Override PartName=\"/word/footnotes.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml\"/>
  <Override PartName=\"/word/endnotes.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml\"/>
  <Override PartName=\"/word/glossary/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml\"/>
'''
    
    # Read existing document.xml to get relationships
    doc_xml = zin.read('word/document.xml')
    
    # Build footnotes.xml
    footnotes_xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<w:footnotes xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"
             xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">
  <w:footnote w:id=\"-1\"/>
  <w:footnote w:id=\"1\">
    <w:p><w:r><w:t>tok_docx_footnote_text_f1</w:t></w:r></w:p>
  </w:footnote>
</w:footnotes>'''

    # Build endnotes.xml
    endnotes_xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<w:endnotes xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">
  <w:endnote w:id=\"-1\"/>
  <w:endnote w:id=\"1\">
    <w:p><w:r><w:t>tok_docx_endnote_text_e1</w:t></w:r></w:p>
  </w:endnote>
</w:endnotes>'''

    # Build glossary document.xml
    glossary_xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<w:glossaryDocument xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">
  <w:docParts>
    <w:docPart>
      <w:docPartBody>
        <w:p><w:r><w:t>tok_docx_glossary_text_g1</w:t></w:r></w:p>
      </w:docPartBody>
    </w:docPart>
  </w:docParts>
</w:glossaryDocument>'''

    # Read word rels, add footnote/endnote/glossary rels
    word_rels = zin.read('word/_rels/document.xml.rels').decode('utf-8')
    footnote_rel = '<Relationship Id=\"rIdFootnotes\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes\" Target=\"footnotes.xml\"/>'
    endnote_rel = '<Relationship Id=\"rIdEndnotes\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/endnotes\" Target=\"endnotes.xml\"/>'
    word_rels = word_rels.replace('</Relationships>', footnote_rel + endnote_rel + '</Relationships>')

    # Add content types for new parts
    ct_data_str = ct_data.decode('utf-8')
    ct_data_str = ct_data_str.replace('</Types>', ct_additions + '</Types>')
    
    # Track existing entries
    existing = set(item.filename for item in zin.infolist())
    
    # Write new ZIP
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == '[Content_Types].xml':
                zout.writestr(item, ct_data_str.encode('utf-8'))
            elif item.filename == 'word/_rels/document.xml.rels':
                zout.writestr(item, word_rels.encode('utf-8'))
            else:
                zout.writestr(item, zin.read(item.filename))
        # Add new parts
        zout.writestr('word/footnotes.xml', footnotes_xml.encode('utf-8'))
        zout.writestr('word/endnotes.xml', endnotes_xml.encode('utf-8'))
        zout.writestr('word/glossary/document.xml', glossary_xml.encode('utf-8'))

os.replace(tmp, src)
print('  sample.docx post-processed')
"

# ================================================================
# 2. sample.xlsx — Excel with all content types
# ================================================================
echo "  sample.xlsx"
run_py "
import openpyxl
from openpyxl import Workbook
from openpyxl.comments import Comment
from openpyxl.worksheet.properties import WorksheetProperties, PageSetupProperties
from openpyxl.utils import get_column_letter

wb = Workbook()

# Core properties
wb.properties.title = 'Sample Spreadsheet'
wb.properties.creator = 'Test Author'
wb.properties.subject = 'Security Review Test'
wb.properties.keywords = 'canary, test, security'

# Sheet 1: normal
ws1 = wb.active
ws1.title = 'Sheet1'
ws1['A1'] = 'tok_xlsx_sheet1_a1'
ws1['B1'] = 'Column B Header'
ws1['A2'] = 42
ws1['B2'] = 'tok_xlsx_sheet1_b2'
# Formula with cached value
ws1['A3'] = '=SUM(A1:A2)'
ws1['A3'].value = '=SUM(A1:A2)'  # formula text
ws1['C3'] = 'Formula: =SUM(1,2) cached: 3'
# Comment
ws1['A1'].comment = Comment('tok_xlsx_comment_a1', 'Reviewer')
# Row hidden
ws1.row_dimensions[5].hidden = True
ws1['A5'] = 'tok_xlsx_hidden_row'
# Column hidden
ws1.column_dimensions[get_column_letter(4)].hidden = True
ws1['D1'] = 'tok_xlsx_hidden_col'

# Sheet 2: hidden
ws2 = wb.create_sheet('Sheet2')
ws2.sheet_state = 'hidden'
ws2['A1'] = 'tok_xlsx_sheet2_hidden_a1'
ws2['B1'] = 'Hidden sheet data'

# Sheet 3: very hidden
ws3 = wb.create_sheet('Sheet3')
ws3.sheet_state = 'veryHidden'
ws3['A1'] = 'tok_xlsx_sheet3_veryhidden_a1'

# Defined names
from openpyxl.workbook.defined_name import DefinedName
dn1 = DefinedName('MyRange', attr_text='Sheet1!\$A\$1:\$B\$3')
dn2 = DefinedName('MyConstant', attr_text='42')
wb.defined_names.add(dn1)
wb.defined_names.add(dn2)

# Shared strings (openpyxl handles this automatically)
ws1['E1'] = 'tok_xlsx_shared_string_1'
ws1['E2'] = 'tok_xlsx_shared_string_2'

# Inline rich text
from openpyxl.cell.rich_text import TextBlock, CellRichText
from openpyxl.cell.text import InlineFont
ws1['F1'] = CellRichText(
    TextBlock(InlineFont(b=True), 'tok_xlsx_'),
    TextBlock(InlineFont(i=True), 'inline_rtf')
)

wb.save('$CORPUS_DIR/sample.xlsx')
print('  sample.xlsx saved')
"

# ================================================================
# 3. sample.pptx — PowerPoint with all content types
# ================================================================
echo "  sample.pptx"
run_py "
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor

prs = Presentation()

# Core properties
prs.core_properties.title = 'Sample Presentation'
prs.core_properties.author = 'Test Author'
prs.core_properties.subject = 'Security Review Test'
prs.core_properties.keywords = 'canary, test, security'

# Slide 1: title + content
slide_layout = prs.slide_layouts[1]  # Title and Content
slide1 = prs.slides.add_slide(slide_layout)
slide1.shapes.title.text = 'Slide 1 Title: tok_pptx_slide1_title'
body = slide1.placeholders[1]
tf = body.text_frame
tf.text = 'tok_pptx_slide1_body_p1_r1'
p = tf.add_paragraph()
p.text = 'tok_pptx_slide1_body_p2_r1'
run = p.add_run()
run.text = ' bold_text'
run.font.bold = True

# Add a shape with text
from pptx.enum.shapes import MSO_SHAPE
shape1 = slide1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(1), Inches(4), Inches(3), Inches(1))
shape1_tf = shape1.text_frame
shape1_tf.text = 'tok_pptx_slide1_shape1_text'

# Slide 2: table
slide2 = prs.slides.add_slide(slide_layout)
slide2.shapes.title.text = 'Slide 2 Table'
table_shape = slide2.shapes.add_table(3, 2, Inches(1), Inches(2), Inches(6), Inches(3))
table = table_shape.table
table.cell(0, 0).text = 'tok_pptx_table_h1_c1'
table.cell(0, 1).text = 'tok_pptx_table_h1_c2'
table.cell(1, 0).text = 'Row1Col1'
table.cell(1, 1).text = 'Row1Col2'
table.cell(2, 0).text = 'Row2Col1'
table.cell(2, 1).text = 'Row2Col2'

# Slide 3: with notes
slide3 = prs.slides.add_slide(slide_layout)
slide3.shapes.title.text = 'Slide 3 With Notes'
notes_slide = slide3.notes_slide
notes_slide.notes_text_frame.text = 'tok_pptx_slide3_notes_text'

# Add comments via XML (pptx comments are in separate XML parts)
# We'll add them via ZIP post-processing

# Slide master
slide_master = prs.slide_masters[0]
# Add text to the master if possible
for shape in slide_master.shapes:
    if shape.has_text_frame:
        shape.text_frame.text = 'tok_pptx_master_text'

prs.save('$CORPUS_DIR/sample.pptx')
print('  sample.pptx saved')
"

# Post-process sample.pptx: add comments
echo "  post-processing sample.pptx (comments)..."
run_py "
import zipfile, os

src = '$CORPUS_DIR/sample.pptx'
tmp = src + '.tmp'

with zipfile.ZipFile(src, 'r') as zin:
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            zout.writestr(item, zin.read(item.filename))
        
        # Add comment for slide 1
        comment_xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<p:cmLst xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"
         xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\"
         xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">
  <p:cm authorId=\"0\" dt=\"2024-01-01T00:00:00\" idx=\"0\">
    <p:pos x=\"1000\" y=\"1000\"/>
    <p:text>tok_pptx_slide1_comment_text</p:text>
  </p:cm>
</p:cmLst>'''
        zout.writestr('ppt/comments/comment1.xml', comment_xml.encode('utf-8'))
        
        # Add comment author
        authors_xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<p:cmAuthorLst xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\">
  <p:cmAuthor id=\"0\" name=\"Reviewer\" initials=\"RV\" lastIndex=\"0\" clrIdx=\"0\"/>
</p:cmAuthorLst>'''
        zout.writestr('ppt/commentAuthors.xml', authors_xml.encode('utf-8'))
        
        # Update Content_Types
        ct_data = zin.read('[Content_Types].xml').decode('utf-8')
        ct_add = '''  <Override PartName=\"/ppt/comments/comment1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.comments+xml\"/>
  <Override PartName=\"/ppt/commentAuthors.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.commentAuthors+xml\"/>'''
        ct_data = ct_data.replace('</Types>', ct_add + '\n</Types>')
        # Re-write with updated CT
        # Need to handle this differently since we already wrote CT
        pass  # We'll handle content types correction below

os.replace(tmp, src)
print('  sample.pptx post-processed')
"

# Fix content types for sample.pptx
run_py "
import zipfile, os

src = '$CORPUS_DIR/sample.pptx'
tmp = src + '.tmp'

with zipfile.ZipFile(src, 'r') as zin:
    with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == '[Content_Types].xml':
                ct_str = data.decode('utf-8')
                if 'ppt/comments/' not in ct_str:
                    ct_add = '''  <Override PartName=\"/ppt/comments/comment1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.comments+xml\"/>
  <Override PartName=\"/ppt/commentAuthors.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.commentAuthors+xml\"/>'''
                    ct_str = ct_str.replace('</Types>', ct_add + '\n</Types>')
                    data = ct_str.encode('utf-8')
            zout.writestr(item, data)

os.replace(tmp, src)
"

# ================================================================
# 4-6. Macro-enabled files (docm, xlsm, pptm) with synthetic vbaProject.bin
# ================================================================

build_vba_bin() {
    local out="$1"
    run_py "
import struct, io

# Build a synthetic vbaProject.bin that looks like an OLE CFB with printable canaries
buf = bytearray()

# OLE CFB header magic
buf += bytes.fromhex('D0CF11E0A1B11AE1')

# Minimal CFB header (512 bytes total)
# Header CLSID (16 bytes) - all zeros
buf += bytes(16)
# Minor version
buf += struct.pack('<H', 0x003E)
# Major version
buf += struct.pack('<H', 0x0003)
# Byte order
buf += struct.pack('<H', 0xFFFE)
# Sector size (512 bytes)
buf += struct.pack('<H', 0x0009)
# Mini sector size (64 bytes)
buf += struct.pack('<H', 0x0006)

# Reserved
buf += bytes(6)
# Number of directory sectors
buf += struct.pack('<I', 0)
# Number of FAT sectors
buf += struct.pack('<I', 1)
# First directory sector location
buf += struct.pack('<I', 1)
# Transaction signature
buf += struct.pack('<I', 1)
# Mini stream cutoff
buf += struct.pack('<I', 4096)
# First mini FAT sector
buf += struct.pack('<I', 0xFFFFFFFE)
# Number of mini FAT sectors
buf += struct.pack('<I', 0)
# First DIFAT sector
buf += struct.pack('<I', 0xFFFFFFFE)
# Number of DIFAT sectors
buf += struct.pack('<I', 0)
# DIFAT entries (109 entries)
for _ in range(109):
    buf += struct.pack('<I', 0xFFFFFFFF)

# Pad to 512 bytes
while len(buf) < 512:
    buf.append(0)

# Add VBA canary strings in ASCII
vba_ascii = b'Sub Macro1()\r\n  MsgBox \"tok_vba_ascii_canary_hello\"\r\nEnd Sub\r\n'
vba_ascii += b'Function Calculate(x)\r\n  Calculate = x * tok_vba_ascii_multiplier\r\nEnd Function\r\n'
buf += vba_ascii

# Pad to align for UTF-16LE
while len(buf) % 2 != 0:
    buf.append(0)

# Add VBA canary strings in UTF-16LE
vba_utf16 = 'Sub Macro2()\r\n  Dim s As String\r\n  s = \"tok_vba_utf16le_canary_world\"\r\nEnd Sub\r\n'
buf += vba_utf16.encode('utf-16-le')

# Pad to 1024 bytes
while len(buf) < 1024:
    buf.append(0)

with open('$out', 'wb') as f:
    f.write(bytes(buf))
"
}

VBA_BIN="$CORPUS_DIR/.vbaProject.bin"
build_vba_bin "$VBA_BIN"

# Inject vbaProject.bin into docx → docm, xlsx → xlsm, pptx → pptm
echo "  sample.docm, sample.xlsm, sample.pptm (injecting vbaProject.bin)..."
run_py "
import zipfile, os, shutil

vba_data = open('$VBA_BIN', 'rb').read()

for (src_name, dst_name, ct_type, rel_type) in [
    ('sample.docx', 'sample.docm', 'application/vnd.ms-office.vbaProject', 'vbaProject'),
    ('sample.xlsx', 'sample.xlsm', 'application/vnd.ms-office.vbaProject', 'vbaProject'),
    ('sample.pptx', 'sample.pptm', 'application/vnd.ms-office.vbaProject', 'vbaProject'),
]:
    src = '$CORPUS_DIR/' + src_name
    dst = '$CORPUS_DIR/' + dst_name
    tmp = dst + '.tmp'
    
    with zipfile.ZipFile(src, 'r') as zin:
        with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)
                if item.filename == '[Content_Types].xml':
                    ct_str = data.decode('utf-8')
                    vba_ct = '  <Default Extension=\"bin\" ContentType=\"application/vnd.ms-office.vbaProject\"/>'
                    if 'vbaProject' not in ct_str:
                        ct_str = ct_str.replace('</Types>', vba_ct + '\n</Types>')
                    data = ct_str.encode('utf-8')
                zout.writestr(item, data)
            # Add vbaProject.bin
            zout.writestr('vbaProject.bin', vba_data)
    
    os.replace(tmp, dst)
    print(f'  {dst_name} saved')
"

rm -f "$VBA_BIN"

# ================================================================
# 7. Legacy Office files (OLE CFB magic)
# ================================================================
echo "  legacy.doc, legacy.xls, legacy.ppt"
run_py "
import struct

# OLE CFB magic bytes
cfb_magic = bytes.fromhex('D0CF11E0A1B11AE1')

# Build minimal OLE CFB header (512 bytes)
ole_header = bytearray()
ole_header += cfb_magic
ole_header += bytes(16)  # CLSID
ole_header += struct.pack('<H', 0x003E)  # minor
ole_header += struct.pack('<H', 0x0003)  # major
ole_header += struct.pack('<H', 0xFFFE)  # byte order
ole_header += struct.pack('<H', 0x0009)  # sector size 512
ole_header += struct.pack('<H', 0x0006)  # mini sector size 64
ole_header += bytes(6)  # reserved
ole_header += struct.pack('<I', 0)  # dir sectors
ole_header += struct.pack('<I', 1)  # FAT sectors
ole_header += struct.pack('<I', 1)  # first dir sector
ole_header += struct.pack('<I', 0)  # transaction sig
ole_header += struct.pack('<I', 4096)  # mini stream cutoff
ole_header += struct.pack('<I', 0xFFFFFFFE)  # first mini FAT
ole_header += struct.pack('<I', 0)  # mini FAT sectors
ole_header += struct.pack('<I', 0xFFFFFFFE)  # first DIFAT
ole_header += struct.pack('<I', 0)  # DIFAT sectors
for _ in range(109):
    ole_header += struct.pack('<I', 0xFFFFFFFF)
# Pad to 512
while len(ole_header) < 512:
    ole_header.append(0)

# Add legacy canary text
legacy_text = b'\\r\\nLEGACY_DOC_CONTENT_CANARY\\r\\nSome legacy document text.\\r\\n'
ole_header += legacy_text * 10  # ~540 bytes of text

data = bytes(ole_header)

for ext in ['.doc', '.xls', '.ppt']:
    with open('$CORPUS_DIR/legacy' + ext, 'wb') as f:
        f.write(data)
    print(f'  legacy{ext} saved')
"

# ================================================================
# 8. Encrypted OOXML (password-protected)
# ================================================================
echo "  encrypted.docx"
run_py "
import zipfile, os

# Create a minimal valid OOXML with EncryptionInfo to signal encryption
tmp = '$CORPUS_DIR/encrypted.docx'
with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as z:
    # Add EncryptionInfo
    z.writestr('EncryptionInfo', b'<?xml version=\"1.0\"?><encryption xmlns=\"http://schemas.microsoft.com/office/2006/encryption\"/>')
    # Add EncryptedPackage
    z.writestr('EncryptedPackage', b'ENCRYPTED_DATA_PLACEHOLDER')
    # Add minimal content types
    ct = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">
  <Default Extension=\"xml\" ContentType=\"application/xml\"/>
</Types>'''
    z.writestr('[Content_Types].xml', ct.encode('utf-8'))
    # Add rels
    rels = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"/>'''
    z.writestr('_rels/.rels', rels.encode('utf-8'))

print('  encrypted.docx saved')
"

# ================================================================
# 9. Corrupt OOXML (valid ZIP, invalid Content_Types.xml)
# ================================================================
echo "  corrupt.docx"
run_py "
import zipfile

tmp = '$CORPUS_DIR/corrupt.docx'
with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as z:
    # Corrupt content types (not valid XML)
    z.writestr('[Content_Types].xml', b'THIS_IS_NOT_VALID_XML<<<>>>')
    # Add a minimal part
    z.writestr('word/document.xml', b'<?xml version=\"1.0\"?><document xmlns=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><body><p><r><t>corrupt test</t></r></p></body></document>')
    # Minimal rels
    rels = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">
  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>
</Relationships>'''
    z.writestr('_rels/.rels', rels.encode('utf-8'))

print('  corrupt.docx saved')
"

# ================================================================
# 10. External relationship OOXML
# ================================================================
echo "  external_rel.docx"
run_py "
import zipfile, os

tmp = '$CORPUS_DIR/external_rel.docx'
with zipfile.ZipFile(tmp, 'w', zipfile.ZIP_DEFLATED) as z:
    ct = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">
  <Default Extension=\"xml\" ContentType=\"application/xml\"/>
  <Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>
  <Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>
</Types>'''
    z.writestr('[Content_Types].xml', ct.encode('utf-8'))
    
    # Add rels with external target
    rels = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">
  <Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>
  <Relationship Id=\"rIdExt\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink\" Target=\"http://localhost:19999/canary\" TargetMode=\"External\"/>
</Relationships>'''
    z.writestr('_rels/.rels', rels.encode('utf-8'))
    
    doc_xml = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">
  <w:body>
    <w:p><w:r><w:t>tok_docx_external_rel_body</w:t></w:r></w:p>
  </w:body>
</w:document>'''
    z.writestr('word/document.xml', doc_xml.encode('utf-8'))
    
    word_rels = '''<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"/>'''
    z.writestr('word/_rels/document.xml.rels', word_rels.encode('utf-8'))

print('  external_rel.docx saved')
"

# ================================================================
# Verify corpus
# ================================================================
echo "=== Corpus verification ==="
ls -la "$CORPUS_DIR"/*.docx "$CORPUS_DIR"/*.xlsx "$CORPUS_DIR"/*.pptx \
      "$CORPUS_DIR"/*.docm "$CORPUS_DIR"/*.xlsm "$CORPUS_DIR"/*.pptm \
      "$CORPUS_DIR"/*.doc "$CORPUS_DIR"/*.xls "$CORPUS_DIR"/*.ppt 2>/dev/null || true

echo "=== Done ==="
