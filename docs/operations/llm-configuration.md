# LLM Configuration

SecurityReviewTool uses an intranet-hosted large language model (LLM) for
semantic review of text regions flagged by deterministic detectors. This
document explains how to configure the LLM connection.

## Requirements

- An **OpenAI-compatible** `chat/completions` HTTP API endpoint.
- The endpoint must be accessible over **HTTPS only** — plain HTTP is rejected.
- The endpoint must be reachable from the user's machine on the corporate
  intranet.
- Authentication via an API key or bearer token passed in the `Authorization`
  HTTP header.

## Configuration

Configuration is managed through the **Settings → LLM** dialog in the
application.

### Endpoint URL

```
https://llm.internal.example.com/v1/chat/completions
```

- Must start with `https://`. If you enter an `http://` URL, the tool
  displays a warning and refuses to connect.
- The path must end with `/chat/completions` (the standard OpenAI-compatible
  chat endpoint).
- IP addresses are accepted but discouraged — prefer FQDN for certificate
  validation.

### Authentication

The tool supports one of:

- **API Key**: A static key sent as `Authorization: Bearer <key>`.
- **Custom Header**: An arbitrary `Authorization` header value you specify
  (e.g., for token-based SSO or proxy authentication).

The credential is stored **encrypted** using AES-256-GCM with a data key
protected by the current Windows user's DPAPI. It is never written to
plaintext on disk.

**Never** paste credentials into notes, chat, email, or configuration files
outside the Settings dialog. The application does not log or export the
credential value.

### Model Name

Specify the model identifier as expected by your endpoint (e.g.,
`gpt-4o-internal`, `claude-3-5-sonnet-internal`). The model name is included
in each API request and must match a model your endpoint serves.

### Prompt

The application ships a default semantic review prompt. A custom prompt can
be configured in Settings. The prompt:

- Must include the placeholder `{EXCERPT}` where detected text is inserted.
- Is subject to the endpoint's context window — the tool truncates excerpts
  to fit the model's maximum input length.
- Is versioned; the prompt version is recorded in scan metadata and exported
  XLSX reports for traceability.

### Concurrency and Rate Limiting

Configure:

| Setting | Default | Description |
|---------|---------|-------------|
| Max concurrent requests | 4 | Maximum simultaneous LLM calls. |
| Retry count | 3 | Attempts per region before marking as `LlmUnavailable`. |
| Retry delay | 2 s | Wait between retries. |

The LLM is called only for text regions already flagged by a deterministic
detector — the tool does not send entire files to the LLM. Each request
contains the detected excerpt and its surrounding context.

## Connection Test

Use the **Test Connection** button in Settings → LLM to verify:

1. The endpoint is reachable.
2. TLS handshake succeeds.
3. Authentication is accepted (HTTP 200 on a minimal chat completion).
4. The model name is recognized by the endpoint.

The test sends a single-turn "Hello" message and checks the response. No scan
data is sent during the connection test.

## Failure Handling

If the LLM endpoint is unreachable during a scan:

- The affected region is marked with gap classification `LlmUnavailable`.
- The scan continues with the remaining deterministic findings.
- The review grid shows which regions were not semantically reviewed.
- The exported XLSX Gaps sheet lists every `LlmUnavailable` region.

No scan data is buffered or retried beyond the configured retry count —
regions that exhaust retries are permanently marked as `LlmUnavailable`.

## Security Model

- **All LLM traffic uses HTTPS.** Plain HTTP is blocked in the UI.
- **Only detected excerpts are sent**, never full files.
- **The LLM is intranet-only** — the tool does not connect to public internet
  LLM services.
- **No telemetry, usage data, or error reports** are sent to any external
  service, including during startup, scan, LLM calls, crash, or shutdown.
- **The worker sandbox has zero network capability** and cannot reach any
  network address (including loopback). All LLM traffic originates from the
  main process only.

## Troubleshooting

| Symptom | Likely Cause | Action |
|---------|-------------|--------|
| "TLS handshake failed" | Endpoint certificate not trusted | Install the internal CA certificate on this machine. |
| "HTTP 401" | Invalid or expired API key | Obtain a fresh key and re-enter in Settings. |
| "HTTP 404" | Wrong endpoint path | Verify the URL ends with `/chat/completions`. |
| "Model not found" | Model name mismatch | Check the model name with your LLM provider. |
| "HTTP 429" | Rate limited | Reduce concurrency or increase retry delay. |
| "Connection timed out" | Network or firewall issue | Verify intranet connectivity; check proxy settings. |
| "LlmUnavailable on all regions" | Endpoint down | Check endpoint health; no scan data is lost — gaps are recorded. |

For persistent issues, see [Diagnostics and Support](diagnostics-and-support.md).
