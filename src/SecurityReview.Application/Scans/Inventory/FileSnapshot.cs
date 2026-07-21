using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans.Inventory;

// Immutable content snapshot taken at broker-open time: identity, declared
// length, last-write UTC, lowercase-hex SHA-256, and the UTC instant the
// snapshot was captured. The hash is a rehashable constant-time key: never
// compare two snapshots by substring; compare the full 64-character hex.
public sealed record FileSnapshot(
    FileStreamIdentity Identity,
    long Length,
    DateTimeOffset LastWriteUtc,
    string Sha256Hex,
    DateTimeOffset CapturedAtUtc);
