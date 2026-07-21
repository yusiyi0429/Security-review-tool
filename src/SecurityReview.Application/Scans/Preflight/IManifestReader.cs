using SecurityReview.Domain.Assets;

namespace SecurityReview.Application.Scans.Preflight;

public static class ManifestErrorCodes
{
    public const string TooLarge = "manifest_too_large";
    public const string EncodingUnsupported = "manifest_encoding_unsupported";
    public const string InvalidJson = "manifest_invalid_json";
    public const string UnknownProperty = "manifest_unknown_property";
    public const string DuplicateProperty = "manifest_duplicate_property";
    public const string MissingProperty = "manifest_missing_property";
    public const string ValueType = "manifest_value_type";
    public const string EmptyValue = "manifest_empty_value";
    public const string StringTooLong = "manifest_string_too_long";
    public const string SchemaVersionUnsupported = "manifest_schema_version_unsupported";
    public const string UnknownAssetType = "manifest_unknown_asset_type";
    public const string UnknownStatus = "manifest_unknown_status";
    public const string PathOutsideRoot = "manifest_path_outside_root";
    public const string ComponentCountOutOfRange = "manifest_component_count_out_of_range";
    public const string ComponentsOverlap = "manifest_components_overlap";
    public const string AuthorizationCountExceeded = "manifest_authorization_count_exceeded";
}

// A stable validation error: machine-readable code plus a JSON Pointer to the
// offending location. The message never echoes the offending value, so an
// attacker-controlled manifest cannot inject content into logs or the UI.
public sealed record ManifestValidationError(string Code, string JsonPointer, string Message);

// Immutable outcome of reading one manifest file. The original bytes are
// fingerprinted so policy can pin decisions to exactly what was read. UI-side
// overrides must produce a new snapshot (`with`), never mutate the asset.
public sealed record ManifestSnapshot(
    AssetManifest? Manifest,
    string? OriginalSha256,
    bool Valid,
    IReadOnlyList<ManifestValidationError> Errors);

public sealed record ManifestReadResult(ManifestSnapshot? Snapshot)
{
    public static ManifestReadResult NotFound { get; } = new((ManifestSnapshot?)null);

    public bool Found => Snapshot is not null;

    public bool Valid => Snapshot?.Valid == true;

    public bool Invalid => Snapshot is { Valid: false };

    public static ManifestReadResult FromSnapshot(ManifestSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return new(snapshot);
    }
}

// Reads and validates the asset manifest below a selected scan root. A missing
// manifest is a result, not an exception: the scanner can operate without one.
public interface IManifestReader
{
    Task<ManifestReadResult> ReadAsync(string scanRootPath, CancellationToken cancellationToken);
}
