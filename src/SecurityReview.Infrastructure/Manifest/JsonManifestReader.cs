using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain.Assets;

namespace SecurityReview.Infrastructure.Manifest;

// Bounded, fail-closed reader for <scan-root>/security-asset-manifest.json.
// Pure managed code: this class must never take a Windows-only dependency.
// Strictness (duplicate tracking, unknown-field rejection, size and depth
// bounds) comes from a hand-rolled Utf8JsonReader pass, not the serializer.
public sealed class JsonManifestReader : IManifestReader
{
    public const string ManifestFileName = "security-asset-manifest.json";
    public const long MaxManifestBytes = 1_048_576; // 1 MiB
    public const int MaxStringLength = 2_048;

    private static readonly JsonReaderOptions ReaderOptions = new()
    {
        CommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        MaxDepth = 16
    };

    public async Task<ManifestReadResult> ReadAsync(string scanRootPath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scanRootPath);
        string path = Path.Combine(scanRootPath, ManifestFileName);
        if (!File.Exists(path))
        {
            return ManifestReadResult.NotFound;
        }

        byte[] bytes;
        await using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, bufferSize: 81_920,
            FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            if (stream.Length > MaxManifestBytes)
            {
                return Invalid(null, [new ManifestValidationError(ManifestErrorCodes.TooLarge,
                    "", "Manifest exceeds the 1 MiB size limit.")]);
            }

            bytes = new byte[stream.Length];
            await stream.ReadExactlyAsync(bytes, cancellationToken).ConfigureAwait(false);
        }

        // Fingerprint the original bytes exactly as read, BOM included.
        string sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes));
        ReadOnlySpan<byte> json = bytes.AsSpan();
        if (json.StartsWith(Utf8Bom))
        {
            json = json[Utf8Bom.Length..];
        }
        else if (HasUnsupportedBom(json))
        {
            return Invalid(sha256, [new ManifestValidationError(
                ManifestErrorCodes.EncodingUnsupported, "",
                "Manifest must be UTF-8 encoded.")]);
        }

        return Parse(json, sha256);
    }

    private static readonly byte[] Utf8Bom = [0xEF, 0xBB, 0xBF];
    private static readonly byte[] Utf32LeBom = [0xFF, 0xFE, 0x00, 0x00];
    private static readonly byte[] Utf32BeBom = [0x00, 0x00, 0xFE, 0xFF];
    private static readonly byte[] Utf16LeBom = [0xFF, 0xFE];
    private static readonly byte[] Utf16BeBom = [0xFE, 0xFF];

    private static bool HasUnsupportedBom(ReadOnlySpan<byte> json) =>
        json.StartsWith(Utf32LeBom)
        || json.StartsWith(Utf32BeBom)
        || json.StartsWith(Utf16LeBom)
        || json.StartsWith(Utf16BeBom);

    private static ManifestReadResult Parse(ReadOnlySpan<byte> json, string sha256)
    {
        var data = new ManifestData();
        var parser = new Parser(json, data);
        parser.ParseDocument();
        if (data.Errors.Count > 0)
        {
            return Invalid(sha256, data.Errors);
        }

        // Structure and per-value semantics are validated; only cross-component
        // overlap remains, which is enforced by the domain factory.
        EvidenceData evidence = data.Evidence!;
        try
        {
            AssetManifest manifest = AssetManifest.Create(data.AssetId!, data.AssetVersion!,
                data.Components!.Select(x => x.Component!).ToList(), MapEvidence(evidence));
            return ManifestReadResult.FromSnapshot(
                new ManifestSnapshot(manifest, sha256, true, []));
        }
        catch (ArgumentException)
        {
            data.Errors.Add(new ManifestValidationError(ManifestErrorCodes.ComponentsOverlap,
                "/components", "Component mappings must not overlap."));
            return Invalid(sha256, data.Errors);
        }
    }

    private static ComplianceEvidence MapEvidence(EvidenceData evidence) =>
        ComplianceEvidence.Create(
            MapDeclaration(evidence.KnowledgeBaseTransformed!),
            MapDeclaration(evidence.ModelFinetuned!),
            evidence.ThirdPartyAuthorizations!
                .Select(x => new ThirdPartyAuthorization(x.Name!, MapDeclaration(x.Declaration)))
                .ToList());

    private static ComplianceDeclaration MapDeclaration(DeclarationData declaration) =>
        new(declaration.ParsedStatus!.Value, declaration.Reference);

    private static ManifestReadResult Invalid(string? sha256,
        IReadOnlyList<ManifestValidationError> errors) =>
        ManifestReadResult.FromSnapshot(new ManifestSnapshot(null, sha256, false, errors));

    private sealed class ManifestData
    {
        public int? SchemaVersion;
        public bool HasSchemaVersion;
        public string? AssetId;
        public bool HasAssetId;
        public string? AssetVersion;
        public bool HasAssetVersion;
        public List<ComponentData>? Components;
        public bool HasComponents;
        public EvidenceData? Evidence;
        public bool HasEvidence;

        public readonly List<ManifestValidationError> Errors = [];
        public readonly List<string> Segments = [];
    }

    private sealed class ComponentData
    {
        public string? Path;
        public bool HasPath;
        public string? AssetType;
        public bool HasAssetType;
        public AssetComponent? Component;
    }

    private sealed class EvidenceData
    {
        public DeclarationData? KnowledgeBaseTransformed;
        public bool HasKnowledgeBaseTransformed;
        public DeclarationData? ModelFinetuned;
        public bool HasModelFinetuned;
        public List<AuthorizationData>? ThirdPartyAuthorizations;
        public bool HasThirdPartyAuthorizations;
    }

    private sealed class DeclarationData
    {
        public string? Status;
        public bool HasStatus;
        public ComplianceEvidenceStatus? ParsedStatus;
        public string? Reference;
        public bool HasReference;
    }

    private sealed class AuthorizationData
    {
        public string? Name;
        public bool HasName;
        public DeclarationData Declaration { get; } = new();
    }

    private ref struct Parser
    {
        private Utf8JsonReader _reader;
        private readonly ManifestData _data;

        public Parser(ReadOnlySpan<byte> json, ManifestData data)
        {
            _reader = new Utf8JsonReader(json, ReaderOptions);
            _data = data;
        }

        private string Pointer => _data.Segments.Count == 0
            ? ""
            : "/" + string.Join('/', _data.Segments);

        public void ParseDocument()
        {
            try
            {
                if (!_reader.Read() || _reader.TokenType != JsonTokenType.StartObject)
                {
                    Error(ManifestErrorCodes.InvalidJson, "Manifest root must be a JSON object.");
                    return;
                }

                ReadRootObject();
                CheckRequiredRootProperties();
                if (_reader.Read())
                {
                    Error(ManifestErrorCodes.InvalidJson,
                        "Manifest contains content after the root object.");
                }
            }
            catch (JsonException)
            {
                Error(ManifestErrorCodes.InvalidJson,
                    "Manifest is not well-formed UTF-8 JSON within the depth limit.");
            }
        }

        private void ReadRootObject()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (ReadPropertyOrEnd(out string name))
            {
                if (!seen.Add(name))
                {
                    Error(ManifestErrorCodes.DuplicateProperty, "Duplicate property name.");
                    _reader.Skip();
                    PopSegment();
                    continue;
                }

                switch (name)
                {
                    case "schema_version":
                        _data.HasSchemaVersion = true;
                        _data.SchemaVersion = ReadInt32();
                        break;
                    case "asset_id":
                        _data.HasAssetId = true;
                        _data.AssetId = ReadString();
                        break;
                    case "asset_version":
                        _data.HasAssetVersion = true;
                        _data.AssetVersion = ReadString();
                        break;
                    case "components":
                        _data.HasComponents = true;
                        _data.Components = ReadComponents();
                        break;
                    case "compliance_evidence":
                        _data.HasEvidence = true;
                        _data.Evidence = ReadEvidence();
                        break;
                    default:
                        Error(ManifestErrorCodes.UnknownProperty,
                            "Unknown top-level property.");
                        _reader.Skip();
                        break;
                }

                PopSegment();
            }
        }

        private void CheckRequiredRootProperties()
        {
            if (!_data.HasSchemaVersion)
            {
                ErrorAt("/schema_version", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }
            else if (_data.SchemaVersion != AssetManifest.SchemaVersion)
            {
                ErrorAt("/schema_version", ManifestErrorCodes.SchemaVersionUnsupported,
                    "Schema version must be exactly 1.");
            }

            CheckRequiredString(_data.HasAssetId, _data.AssetId, "/asset_id");
            CheckRequiredString(_data.HasAssetVersion, _data.AssetVersion, "/asset_version");
            if (!_data.HasComponents)
            {
                ErrorAt("/components", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }

            if (!_data.HasEvidence)
            {
                ErrorAt("/compliance_evidence", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }
        }

        private void CheckRequiredString(bool present, string? value, string pointer)
        {
            if (!present)
            {
                ErrorAt(pointer, ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }
            else if (string.IsNullOrWhiteSpace(value))
            {
                ErrorAt(pointer, ManifestErrorCodes.EmptyValue,
                    "Value must be a non-empty string.");
            }
        }

        private List<ComponentData> ReadComponents()
        {
            var components = new List<ComponentData>();
            if (_reader.TokenType != JsonTokenType.StartArray)
            {
                Error(ManifestErrorCodes.ValueType, "Expected an array of components.");
                _reader.Skip();
                return components;
            }

            int index = 0;
            while (ReadArrayItemOrEnd())
            {
                _data.Segments.Add(index.ToString(CultureInfo.InvariantCulture));
                components.Add(ReadComponent());
                PopSegment();
                index++;
            }

            if (components.Count is < 1 or > AssetManifest.MaxComponents)
            {
                Error(ManifestErrorCodes.ComponentCountOutOfRange,
                    "Manifest must declare 1 to 1,000 component mappings.");
            }

            return components;
        }

        private ComponentData ReadComponent()
        {
            var component = new ComponentData();
            if (_reader.TokenType != JsonTokenType.StartObject)
            {
                Error(ManifestErrorCodes.ValueType, "Expected a component object.");
                _reader.Skip();
                return component;
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (ReadPropertyOrEnd(out string name))
            {
                if (!seen.Add(name))
                {
                    Error(ManifestErrorCodes.DuplicateProperty, "Duplicate property name.");
                    _reader.Skip();
                    PopSegment();
                    continue;
                }

                switch (name)
                {
                    case "path":
                        component.HasPath = true;
                        component.Path = ReadString();
                        break;
                    case "asset_type":
                        component.HasAssetType = true;
                        component.AssetType = ReadString();
                        break;
                    default:
                        Error(ManifestErrorCodes.UnknownProperty,
                            "Unknown component property.");
                        _reader.Skip();
                        break;
                }

                PopSegment();
            }

            ValidateComponent(component);
            return component;
        }

        private void ValidateComponent(ComponentData component)
        {
            if (!component.HasPath)
            {
                ErrorAt(Pointer + "/path", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }

            AssetTypeId? type = null;
            if (!component.HasAssetType)
            {
                ErrorAt(Pointer + "/asset_type", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }
            else if (component.AssetType is not null)
            {
                try
                {
                    type = AssetTypeId.Parse(component.AssetType);
                }
                catch (ArgumentException)
                {
                    ErrorAt(Pointer + "/asset_type", ManifestErrorCodes.UnknownAssetType,
                        "Unknown asset type.");
                }
            }

            if (component.Path is null)
            {
                return;
            }

            try
            {
                // Path validation is type-independent; the probe type is only a
                // placeholder when the declared type was itself invalid.
                component.Component = AssetComponent.Create(component.Path,
                    type ?? AssetTypeId.Parse("ASSET-001"));
            }
            catch (ArgumentException)
            {
                ErrorAt(Pointer + "/path", ManifestErrorCodes.PathOutsideRoot,
                    "Component path must remain below the scan root.");
            }
        }

        private EvidenceData ReadEvidence()
        {
            var evidence = new EvidenceData();
            if (_reader.TokenType != JsonTokenType.StartObject)
            {
                Error(ManifestErrorCodes.ValueType, "Expected a compliance evidence object.");
                _reader.Skip();
                return evidence;
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (ReadPropertyOrEnd(out string name))
            {
                if (!seen.Add(name))
                {
                    Error(ManifestErrorCodes.DuplicateProperty, "Duplicate property name.");
                    _reader.Skip();
                    PopSegment();
                    continue;
                }

                switch (name)
                {
                    case "knowledge_base_transformed":
                        evidence.HasKnowledgeBaseTransformed = true;
                        evidence.KnowledgeBaseTransformed = ReadDeclaration();
                        break;
                    case "model_finetuned":
                        evidence.HasModelFinetuned = true;
                        evidence.ModelFinetuned = ReadDeclaration();
                        break;
                    case "third_party_authorizations":
                        evidence.HasThirdPartyAuthorizations = true;
                        evidence.ThirdPartyAuthorizations = ReadAuthorizations();
                        break;
                    default:
                        Error(ManifestErrorCodes.UnknownProperty,
                            "Unknown compliance evidence property.");
                        _reader.Skip();
                        break;
                }

                PopSegment();
            }

            if (!evidence.HasKnowledgeBaseTransformed)
            {
                ErrorAt(Pointer + "/knowledge_base_transformed",
                    ManifestErrorCodes.MissingProperty, "Required property is missing.");
            }

            if (!evidence.HasModelFinetuned)
            {
                ErrorAt(Pointer + "/model_finetuned", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }

            if (!evidence.HasThirdPartyAuthorizations)
            {
                ErrorAt(Pointer + "/third_party_authorizations",
                    ManifestErrorCodes.MissingProperty, "Required property is missing.");
            }

            return evidence;
        }

        private DeclarationData ReadDeclaration()
        {
            var declaration = new DeclarationData();
            if (_reader.TokenType != JsonTokenType.StartObject)
            {
                Error(ManifestErrorCodes.ValueType, "Expected a declaration object.");
                _reader.Skip();
                return declaration;
            }

            ReadDeclarationBody(declaration);
            if (!declaration.HasStatus)
            {
                ErrorAt(Pointer + "/status", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }

            if (!declaration.HasReference)
            {
                ErrorAt(Pointer + "/reference", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }

            return declaration;
        }

        private void ReadDeclarationBody(DeclarationData declaration)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (ReadPropertyOrEnd(out string name))
            {
                if (!seen.Add(name))
                {
                    Error(ManifestErrorCodes.DuplicateProperty, "Duplicate property name.");
                    _reader.Skip();
                    PopSegment();
                    continue;
                }

                switch (name)
                {
                    case "status":
                        declaration.HasStatus = true;
                        declaration.Status = ReadString();
                        declaration.ParsedStatus = ParseStatus(declaration.Status);
                        break;
                    case "reference":
                        declaration.HasReference = true;
                        declaration.Reference = ReadNullableString();
                        break;
                    default:
                        Error(ManifestErrorCodes.UnknownProperty,
                            "Unknown declaration property.");
                        _reader.Skip();
                        break;
                }

                PopSegment();
            }
        }

        private ComplianceEvidenceStatus? ParseStatus(string? status)
        {
            if (status is null)
            {
                return null;
            }

            try
            {
                return ComplianceDeclaration.ParseStatus(status);
            }
            catch (ArgumentException)
            {
                Error(ManifestErrorCodes.UnknownStatus,
                    "Unknown compliance evidence status.");
                return null;
            }
        }

        private List<AuthorizationData> ReadAuthorizations()
        {
            var authorizations = new List<AuthorizationData>();
            if (_reader.TokenType != JsonTokenType.StartArray)
            {
                Error(ManifestErrorCodes.ValueType,
                    "Expected an array of third-party authorizations.");
                _reader.Skip();
                return authorizations;
            }

            int index = 0;
            while (ReadArrayItemOrEnd())
            {
                _data.Segments.Add(index.ToString(CultureInfo.InvariantCulture));
                authorizations.Add(ReadAuthorization());
                PopSegment();
                index++;
            }

            if (authorizations.Count > ComplianceEvidence.MaxThirdPartyAuthorizations)
            {
                Error(ManifestErrorCodes.AuthorizationCountExceeded,
                    "Manifest must declare at most 1,000 third-party authorizations.");
            }

            return authorizations;
        }

        private AuthorizationData ReadAuthorization()
        {
            var authorization = new AuthorizationData();
            if (_reader.TokenType != JsonTokenType.StartObject)
            {
                Error(ManifestErrorCodes.ValueType, "Expected an authorization object.");
                _reader.Skip();
                return authorization;
            }

            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (ReadPropertyOrEnd(out string name))
            {
                if (!seen.Add(name))
                {
                    Error(ManifestErrorCodes.DuplicateProperty, "Duplicate property name.");
                    _reader.Skip();
                    PopSegment();
                    continue;
                }

                switch (name)
                {
                    case "name":
                        authorization.HasName = true;
                        authorization.Name = ReadString();
                        break;
                    case "status":
                        authorization.Declaration.HasStatus = true;
                        authorization.Declaration.Status = ReadString();
                        authorization.Declaration.ParsedStatus =
                            ParseStatus(authorization.Declaration.Status);
                        break;
                    case "reference":
                        authorization.Declaration.HasReference = true;
                        authorization.Declaration.Reference = ReadNullableString();
                        break;
                    default:
                        Error(ManifestErrorCodes.UnknownProperty,
                            "Unknown authorization property.");
                        _reader.Skip();
                        break;
                }

                PopSegment();
            }

            if (!authorization.HasName)
            {
                ErrorAt(Pointer + "/name", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }
            else if (string.IsNullOrWhiteSpace(authorization.Name))
            {
                ErrorAt(Pointer + "/name", ManifestErrorCodes.EmptyValue,
                    "Value must be a non-empty string.");
            }

            if (!authorization.Declaration.HasStatus)
            {
                ErrorAt(Pointer + "/status", ManifestErrorCodes.MissingProperty,
                    "Required property is missing.");
            }

            return authorization;
        }

        private string? ReadString()
        {
            if (_reader.TokenType != JsonTokenType.String)
            {
                Error(ManifestErrorCodes.ValueType, "Expected a string value.");
                _reader.Skip();
                return null;
            }

            string value = _reader.GetString()!;
            if (value.Length > MaxStringLength)
            {
                Error(ManifestErrorCodes.StringTooLong,
                    "String exceeds 2,048 characters.");
                return null;
            }

            return value;
        }

        private string? ReadNullableString()
        {
            if (_reader.TokenType == JsonTokenType.Null)
            {
                return null;
            }

            return ReadString();
        }

        private int? ReadInt32()
        {
            if (_reader.TokenType != JsonTokenType.Number
                || !_reader.TryGetInt32(out int value))
            {
                Error(ManifestErrorCodes.ValueType, "Expected an integer value.");
                _reader.Skip();
                return null;
            }

            return value;
        }

        // Positions the reader on the value of the next property and returns
        // its name, or returns false once the current object ends.
        private bool ReadPropertyOrEnd(out string name)
        {
            name = "";
            if (!_reader.Read())
            {
                Error(ManifestErrorCodes.InvalidJson, "Unexpected end of manifest.");
                return false;
            }

            if (_reader.TokenType == JsonTokenType.EndObject)
            {
                return false;
            }

            // The reader state machine guarantees a property name here.
            name = _reader.GetString()!;
            _data.Segments.Add(EscapePointerSegment(name));
            if (!_reader.Read())
            {
                Error(ManifestErrorCodes.InvalidJson, "Unexpected end of manifest.");
                return false;
            }

            return true;
        }

        // Positions the reader on the next array element, or returns false
        // once the current array ends.
        private bool ReadArrayItemOrEnd()
        {
            if (!_reader.Read())
            {
                Error(ManifestErrorCodes.InvalidJson, "Unexpected end of manifest.");
                return false;
            }

            return _reader.TokenType != JsonTokenType.EndArray;
        }

        private void PopSegment() => _data.Segments.RemoveAt(_data.Segments.Count - 1);

        private void Error(string code, string message) =>
            _data.Errors.Add(new ManifestValidationError(code, Pointer, message));

        private void ErrorAt(string pointer, string code, string message) =>
            _data.Errors.Add(new ManifestValidationError(code, pointer, message));

        private static string EscapePointerSegment(string segment) => segment
            .Replace("~", "~0", StringComparison.Ordinal)
            .Replace("/", "~1", StringComparison.Ordinal);
    }
}
