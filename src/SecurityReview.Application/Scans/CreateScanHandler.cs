using System.Text;
using System.Text.Json;
using SecurityReview.Application.Abstractions;
using SecurityReview.Application.Scans.Preflight;
using SecurityReview.Domain;
using SecurityReview.Domain.Scans;

namespace SecurityReview.Application.Scans;

/// <summary>
/// Outcome of <see cref="CreateScanHandler"/>. Either a fully materialised
/// scan id + immutable snapshot hash, or a preflight failure with the
/// machine-readable error codes the UI must surface verbatim.
/// </summary>
public sealed record CreateScanResult(
    bool Created,
    ScanId? ScanId,
    string? ConfigHash,
    DateTimeOffset? CapturedAtUtc,
    IReadOnlyList<PreflightError> Errors)
{
    public static CreateScanResult Failure(IReadOnlyList<PreflightError> errors) =>
        new(false, null, null, null, errors);

    public static CreateScanResult Success(ScanId scanId, string configHash, DateTimeOffset capturedAtUtc) =>
        new(true, scanId, configHash, capturedAtUtc, Array.Empty<PreflightError>());
}

/// <summary>
/// Creates a new scan run: validates inputs, captures the immutable
/// preflight snapshot, persists the snapshot row and the draft scan
/// row. The orchestrator and every later stage only ever see the
/// snapshot — concurrent UI edits after <see cref="StartScanHandler"/>
/// only affect future scans.
/// </summary>
public sealed class CreateScanHandler
{
    private readonly IScanRepository _scanRepository;
    private readonly IScanSnapshotRepository _snapshotRepository;
    private readonly IPayloadProtector _protector;
    private readonly Func<DateTimeOffset> _clock;

    public CreateScanHandler(
        IScanRepository scanRepository,
        IScanSnapshotRepository snapshotRepository,
        IPayloadProtector protector,
        Func<DateTimeOffset>? clock = null)
    {
        _scanRepository = scanRepository ?? throw new ArgumentNullException(nameof(scanRepository));
        _snapshotRepository = snapshotRepository ?? throw new ArgumentNullException(nameof(snapshotRepository));
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Validates <paramref name="command"/>, computes the snapshot hash
    /// and persists the snapshot row alongside a Draft <see cref="ScanRun"/>.
    /// </summary>
    public async Task<CreateScanResult> HandleAsync(
        CreateScanCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var errors = new List<PreflightError>();
        try
        {
            command.Validate();
        }
        catch (InvalidScanInputException ex)
        {
            errors.Add(new PreflightError("invalid_scan_input", ex.Message));
            return CreateScanResult.Failure(errors);
        }

        var snapshot = new ScanConfigurationSnapshot(
            RootPaths: command.RootPaths.ToArray(),
            Manifest: command.Manifest,
            UiOverrideComponentIds: command.UiOverrideComponentIds.ToArray(),
            ExclusionPatterns: command.ExclusionPatterns.ToArray(),
            ActiveRulePackHash: command.ActiveRulePackHash,
            PolicySha256: command.PolicySha256,
            LlmEndpointFingerprint: command.LlmEndpointFingerprint,
            LlmModelFingerprint: command.LlmModelFingerprint,
            ClientVersion: command.ClientVersion,
            ParserAdapterVersion: command.ParserAdapterVersion,
            DetectorAdapterVersion: command.DetectorAdapterVersion,
            PromptVersion: command.PromptVersion,
            Sandbox: command.Sandbox,
            EffectiveDetectorVersions: command.EffectiveDetectorVersions.ToArray(),
            CapturedAtUtc: _clock());

        string hash = snapshot.ComputeHash();
        ScanId scanId = new(Guid.NewGuid());
        DateTimeOffset capturedAtUtc = _clock();

        ScanRun draft = new(
            ScanId: scanId,
            Status: ScanStatus.Draft,
            CreatedAtUtc: capturedAtUtc,
            UpdatedAtUtc: capturedAtUtc,
            RuleFingerprint: command.ActiveRulePackHash,
            ClientFingerprint: command.LlmEndpointFingerprint,
            PipelineFingerprint: hash,
            PlannedCount: 0,
            Version: 1);

        await _scanRepository.InsertAsync(draft, cancellationToken).ConfigureAwait(false);

        byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(snapshot));
        byte[] encrypted = EncryptSnapshot(scanId, payloadBytes);

        var record = new ScanSnapshotRecord(
            ScanId: scanId,
            CapturedAtUtc: capturedAtUtc,
            ConfigHash: hash,
            ActiveRulePackHash: command.ActiveRulePackHash,
            PolicySha256: command.PolicySha256,
            LlmEndpointFingerprint: command.LlmEndpointFingerprint,
            LlmModelFingerprint: command.LlmModelFingerprint,
            ClientVersion: command.ClientVersion,
            ParserAdapterVersion: command.ParserAdapterVersion,
            DetectorAdapterVersion: command.DetectorAdapterVersion,
            PromptVersion: command.PromptVersion,
            SandboxWorkerSha256: command.Sandbox.WorkerSha256,
            EncryptedPayload: encrypted);

        await _snapshotRepository.InsertAsync(scanId, record, cancellationToken)
            .ConfigureAwait(false);

        return CreateScanResult.Success(scanId, hash, capturedAtUtc);
    }

    private byte[] EncryptSnapshot(ScanId scanId, byte[] plaintext)
    {
        EncryptedPayload envelope = _protector.Protect(
            "scan_config_snapshots",
            scanId.Value.ToString(),
            "encrypted_payload",
            plaintext);
        return JsonSerializer.SerializeToUtf8Bytes(envelope,
            SnapshotJsonContext.Default.EncryptedPayload);
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(EncryptedPayload))]
internal sealed partial class SnapshotJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
