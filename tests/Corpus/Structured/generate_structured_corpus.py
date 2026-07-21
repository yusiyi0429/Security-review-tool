#!/usr/bin/env python3
"""Generate structured format corpus fixtures for parser testing."""

import json
import os
import sys


def write_file(path: str, content: bytes | str):
    if isinstance(content, str):
        content = content.encode("utf-8")
    full = os.path.join(OUTPUT_DIR, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(content)
    print(f"  Wrote: {path}")


def gen_json() -> None:
    # --- Valid JSON ---
    # Simple object
    write_file(
        "json/valid_simple.json",
        json.dumps({"name": "test", "value": 42, "active": True, "data": None}, indent=2),
    )

    # Nested with arrays - token at /users/1/token
    write_file(
        "json/valid_nested.json",
        json.dumps(
            {
                "users": [
                    {"id": 1, "name": "Alice", "token": "tok_alice_123"},
                    {"id": 2, "name": "Bob", "token": "tok_bob_456"},
                ],
                "metadata": {"version": "1.0"},
            },
            indent=2,
        ),
    )

    # Array root
    write_file(
        "json/valid_array.json",
        json.dumps([1, 2, 3, {"nested": True}], indent=2),
    )

    # Various types
    write_file(
        "json/valid_types.json",
        json.dumps(
            {
                "int_val": 42,
                "float_val": 3.14,
                "neg_val": -1,
                "str_val": "hello",
                "bool_true": True,
                "bool_false": False,
                "null_val": None,
                "empty_arr": [],
                "empty_obj": {},
            },
            indent=2,
        ),
    )

    # String with special chars (escaped)
    write_file(
        "json/valid_escaped.json",
        json.dumps({"path": "/users/1", "quote": 'he said "hello"', "slash": "a/b/c"}, indent=2),
    )

    # Unicode
    write_file(
        "json/valid_unicode.json",
        json.dumps({"greeting": "你好世界", "emoji": "😀"}, indent=2, ensure_ascii=False),
    )

    # Deep nesting (within limits)
    def build_deep(depth: int) -> dict:
        if depth == 0:
            return {"leaf": f"value_at_{depth}"}
        return {"child": build_deep(depth - 1)}

    write_file("json/valid_depth_50.json", json.dumps(build_deep(50), indent=2))

    # --- Adversarial JSON ---

    # Duplicate keys
    write_file("json/adversarial_duplicate_keys.json", b'{"a":1,"b":2,"a":3}')

    # Unclosed string
    write_file("json/adversarial_unclosed_string.json", b'{"key": "unclosed')

    # Trailing comma in object
    write_file("json/adversarial_trailing_comma.json", b'{"a":1,}')

    # Trailing comma in array
    write_file("json/adversarial_trailing_comma_array.json", b'[1,2,]')

    # Invalid literal
    write_file("json/adversarial_invalid_literal.json", b'{"a":tru}')

    # NUL byte injection
    write_file("json/adversarial_nul.json", b'{"a": "has\x00nul"}')

    # Large string (> 64 KiB but < 1 MiB)
    large_str = "A" * 128 * 1024
    write_file(
        "json/adversarial_large_string.json",
        b'{"key":"' + large_str.encode() + b'"}',
    )

    # Deep nesting beyond limit (>128)
    deep_obj = {"a": 1}
    for _ in range(130):
        deep_obj = {"nested": deep_obj}
    write_file("json/adversarial_depth_130.json", json.dumps(deep_obj).encode())

    # Invalid token
    write_file("json/adversarial_invalid_token.json", b'{"a":1]')

    # Empty
    write_file("json/adversarial_empty.json", b"")

    # Single value (valid JSON, not object/array)
    write_file("json/adversarial_single_value.json", b'"just a string"')

    # Comment (disallowed in strict JSON)
    write_file("json/adversarial_comment.json", b"// comment\n42")


def gen_xml() -> None:
    # --- Valid XML ---
    write_file(
        "xml/valid_simple.xml",
        '<?xml version="1.0" encoding="UTF-8"?>\n<root><name>test</name><value>42</value></root>',
    )

    # Nested with token at /root/user[2]/token
    write_file(
        "xml/valid_nested.xml",
        (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<users>\n"
            '  <user id="1"><name>Alice</name><token>tok_alice_123</token></user>\n'
            '  <user id="2"><name>Bob</name><token>tok_bob_456</token></user>\n'
            "</users>"
        ),
    )

    # Attributes
    write_file(
        "xml/valid_attributes.xml",
        '<root><item key="k1" value="v1"/><item key="k2" value="v2" enabled="true"/></root>',
    )

    # Comments and PI
    write_file(
        "xml/valid_comments_pi.xml",
        '<?xml version="1.0"?>\n<?target data?>\n<!-- comment -->\n<root>text</root>',
    )

    # Deep nesting
    deep_xml = "<root>" + "".join(f"<a{i}>" for i in range(60)) + "leaf" + "".join(f"</a{i}>" for i in range(59, -1, -1)) + "</root>"
    write_file("xml/valid_depth_60.xml", deep_xml)

    # --- Adversarial XML ---

    # DTD
    write_file(
        "xml/adversarial_dtd.xml",
        '<!DOCTYPE root [<!ENTITY e "entity">]>\n<root>&e;</root>',
    )

    # XXE attempt
    write_file(
        "xml/adversarial_xxe.xml",
        '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<root>&xxe;</root>',
    )

    # Unclosed tag
    write_file("xml/adversarial_unclosed.xml", "<root><a>content</a><b>unclosed</root>")

    # Malformed
    write_file("xml/adversarial_malformed.xml", "<root><a>ok</a><b>bad</c></root>")

    # Entity reference without DTD
    write_file("xml/adversarial_entity_ref.xml", "<root>&unknown;</root>")

    # Empty
    write_file("xml/adversarial_empty.xml", "")

    # Not XML
    write_file("xml/adversarial_not_xml.xml", "this is not xml at all")


def gen_csv() -> None:
    # --- Valid CSV (comma) ---
    write_file(
        "csv/valid_comma.csv",
        "id,name,token\n1,Alice,tok_alice_123\n2,Bob,tok_bob_456\n3,Charlie,tok_charlie_789\n",
    )

    # Tab separated
    write_file(
        "csv/valid_tab.tsv",
        "id\tname\ttoken\n1\tAlice\ttok_alice_123\n2\tBob\ttok_bob_456\n",
    )

    # Semicolon
    write_file(
        "csv/valid_semicolon.csv",
        "id;name;token\n1;Alice;tok_alice_123\n2;Bob;tok_bob_456\n",
    )

    # Pipe
    write_file(
        "csv/valid_pipe.csv",
        "id|name|token\n1|Alice|tok_alice_123\n2|Bob|tok_bob_456\n",
    )

    # Quoted fields with commas
    write_file(
        "csv/valid_quoted.csv",
        'id,description,value\n1,"hello, world",42\n2,"quote ""inside""",99\n',
    )

    # Quoted with newlines
    write_file(
        "csv/valid_quoted_newlines.csv",
        'id,text\n1,"line1\nline2"\n2,"line3\nline4\nline5"\n',
    )

    # No header
    write_file(
        "csv/valid_no_header.csv",
        "1,Alice,token1\n2,Bob,token2\n3,Charlie,token3\n",
    )

    # CRLF line endings
    write_file("csv/valid_crlf.csv", b"id,name\r\n1,Alice\r\n2,Bob\r\n")

    # --- Adversarial CSV ---

    # Unclosed quote
    write_file(
        "csv/adversarial_unclosed_quote.csv",
        'id,text\n1,"hello world\n2,"goodbye"\n',
    )

    # Ambiguous delimiter (mixed)
    write_file(
        "csv/adversarial_ambiguous.csv",
        "a,b,c\n1,2,3\n4;5;6\n7,8,9\n",
    )

    # Too many columns
    many_cols = ",".join("col" + str(i) for i in range(200)) + "\n" + ",".join("val" + str(i) for i in range(200)) + "\n"
    write_file("csv/adversarial_many_columns.csv", many_cols)

    # Large field
    large_field = "X" * (100 * 1024)  # 100 KiB
    write_file("csv/adversarial_large_field.csv", f"id,data\n1,{large_field}\n")

    # Embedded NUL
    write_file("csv/adversarial_nul.csv", b"id,name\n1,has\x00nul\n")

    # Empty
    write_file("csv/adversarial_empty.csv", "")

    # Single column
    write_file("csv/adversarial_single_column.csv", "value\n1\n2\n3\n")

    # Only header
    write_file("csv/adversarial_header_only.csv", "id,name,token\n")


def gen_yaml() -> None:
    # --- Valid YAML ---
    write_file(
        "yaml/valid_simple.yaml",
        "name: test\nvalue: 42\nactive: true\ndata: null\n",
    )

    # Nested with token
    write_file(
        "yaml/valid_nested.yaml",
        (
            "users:\n"
            "  - id: 1\n"
            "    name: Alice\n"
            "    token: tok_alice_123\n"
            "  - id: 2\n"
            "    name: Bob\n"
            "    token: tok_bob_456\n"
            "metadata:\n"
            "  version: '1.0'\n"
        ),
    )

    # Sequence
    write_file("yaml/valid_sequence.yaml", "- red\n- green\n- blue\n")

    # Flow style
    write_file("yaml/valid_flow.yaml", "{name: test, values: [1, 2, 3]}\n")

    # Multiline strings
    write_file(
        "yaml/valid_multiline.yaml",
        "description: |\n  line one\n  line two\n  line three\n",
    )

    # Anchors and aliases
    write_file(
        "yaml/valid_anchors.yaml",
        "defaults: &defaults\n  timeout: 30\n  retries: 3\nservice1:\n  <<: *defaults\n  name: svc1\n",
    )

    # --- Adversarial YAML ---

    # Custom tag
    write_file("yaml/adversarial_custom_tag.yaml", "value: !custom_tag some data\n")

    # Deep nesting
    deep_yaml = "root:\n" + "".join(f"{'  ' * (i+1)}child:\n" for i in range(130)) + f"{'  ' * 130}leaf: value\n"
    write_file("yaml/adversarial_deep.yaml", deep_yaml)

    # Tags
    write_file("yaml/adversarial_tags.yaml", "---\n%TAG !e! tag:example.com,2024:\n---\n- !e!foo bar\n")

    # Empty
    write_file("yaml/adversarial_empty.yaml", "")

    # Binary data (not valid UTF-8 in scalars)
    write_file("yaml/adversarial_binary.yaml", b'\x00\x01\x02not valid yaml')

    # Large document (> 64 MiB signal, but we'll make a smaller test)
    large_yaml = "# Large YAML\n" + "".join(f"- item_{i}: value_{i}\n" for i in range(1000))
    write_file("yaml/adversarial_large.yaml", large_yaml)


def main() -> None:
    gen_json()
    gen_xml()
    gen_csv()
    gen_yaml()

    # Summary
    print("\nCorpus generation complete.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: generate_structured_corpus.py <output_dir>")
        sys.exit(1)
    OUTPUT_DIR = sys.argv[1]
    main()
