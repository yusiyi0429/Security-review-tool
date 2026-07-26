using System.Formats.Tar;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using SecurityReview.Domain;
using SecurityReview.Domain.Assets;
using SecurityReview.Domain.Scans;
using SecurityReview.ParserContracts.Parsing;
using SecurityReview.Parsers.Archives;
using SecurityReview.Parsers.Core;

namespace SecurityReview.Parsers.Oci;

/// <summary>
/// Parses <c>docker save</c> TAR archives. The worker receives a seekable
/// stream over the TAR, parses the top-level <c>manifest.json</c>, the config
/// blob, and each listed layer. It never contacts a daemon, socket, or registry.
/// </summary>
public sealed class DockerArchiveParser : IFormatParser
{
    private static readonly JsonSerializerOptions ManifestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };
    public string ParserId => "docker-archive";
    public Version ParserVersion => new(1, 0, 0);

    public bool CanParse(FormatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        return probe.Format.FormatId == "docker-archive"
            || probe.Format.FormatId == "tar"
            && (probe.ExtensionHint?.Contains("docker", StringComparison.OrdinalIgnoreCase) == true
                || probe.ExtensionHint?.Contains("oci", StringComparison.OrdinalIgnoreCase) == true
                || probe.ExtensionHint?.Contains("container", StringComparison.OrdinalIgnoreCase) == true);
    }

    public async IAsyncEnumerable<ParserEvent> ParseAsync(
        ParserInput input,
        ParseContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(context);

        List<ParserEvent> events;
        try
        {
            events = await CollectEventsAsync(input, context, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            events =
            [
                new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                    "docker-archive", "parse", GapReason.Corrupt,
                    $"unexpected: {ex.Message}", null, null, DateTimeOffset.UtcNow)),
                new ParserEvent.ParseCompleted()
            ];
        }

        foreach (var evt in events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return evt;
        }
    }

    private static async Task<List<ParserEvent>> CollectEventsAsync(
        ParserInput input,
        ParseContext context,
        CancellationToken cancellationToken)
    {
        var events = new List<ParserEvent>();
        Stream sourceStream = input.Stream;
        if (!sourceStream.CanSeek)
            throw new ArgumentException("Docker archive parsing requires a seekable stream.", nameof(input));

        sourceStream.Position = 0;
        var budget = new ArchiveBudget(context.Limits.MaxExpandedBytesRemaining);

        // Step 1: Read all top-level TAR entries into memory keyed by name.
        var tarEntries = new Dictionary<string, (TarEntry Entry, byte[] Data)>(StringComparer.Ordinal);
        using var reader = new TarReader(sourceStream, leaveOpen: true);

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            TarEntry? entry = await reader.GetNextEntryAsync(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (entry == null) break;

            string entryName = entry.Name.TrimEnd('/');

            // Budget check
            var reserve = budget.TryReserve(1, entry.Length, entry.Length, 1);
            if (!reserve.Succeeded)
            {
                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null,
                    $"{context.VirtualPath}!/{entryName}",
                    "docker-archive", "budget", GapReason.ArchiveLimit,
                    reserve.DetailCode ?? "budget_exceeded",
                    entry.Length, 0, DateTimeOffset.UtcNow)));
                continue;
            }

            // Read entry data (bounded)
            long maxRead = Math.Min(entry.Length, ArchiveBudget.MaxBytesPerEntry);
            if (maxRead > int.MaxValue) maxRead = int.MaxValue;

            Stream? dataStream = entry.DataStream;
            if (dataStream is null)
            {
                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null, $"{context.VirtualPath}!/{entryName}",
                    "docker-archive", "entry_read", GapReason.Corrupt,
                    "null_data_stream", entry.Length, 0, DateTimeOffset.UtcNow)));
                continue;
            }

            var buffer = new byte[(int)maxRead];
            int totalRead = 0;
            int read;
            while (totalRead < buffer.Length
                && (read = await dataStream.ReadAsync(
                    buffer.AsMemory(totalRead, buffer.Length - totalRead),
                    cancellationToken).ConfigureAwait(false)) > 0)
            {
                totalRead += read;
            }

            tarEntries[entryName] = (entry, buffer[..totalRead]);
        }

        // Step 2: Find and parse manifest.json
        if (!tarEntries.TryGetValue("manifest.json", out var manifestEntry))
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                "docker-archive", "manifest", GapReason.Corrupt,
                "manifest_json_missing", null, null, DateTimeOffset.UtcNow)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        DockerSaveManifest[] manifestRecords;
        try
        {
            manifestRecords = JsonSerializer.Deserialize<DockerSaveManifest[]>(
                manifestEntry.Data, ManifestJsonOptions)!;
        }
        catch (Exception ex)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                "docker-archive", "manifest_parse", GapReason.Corrupt,
                $"manifest_parse_error: {ex.Message}", manifestEntry.Data.Length, 0,
                DateTimeOffset.UtcNow)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        if (manifestRecords is null || manifestRecords.Length == 0)
        {
            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                Guid.NewGuid(), context.ScanId, null, context.VirtualPath,
                "docker-archive", "manifest", GapReason.Corrupt,
                "manifest_empty", null, null, DateTimeOffset.UtcNow)));
            events.Add(new ParserEvent.ParseCompleted());
            return events;
        }

        // Step 3: Parse config and layers for each record
        int recordIndex = 0;
        foreach (var record in manifestRecords)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // Emit repo tags as metadata
            if (record.RepoTags is { Length: > 0 })
            {
                string tagText = string.Join("\n", record.RepoTags.Select(t => $"repo_tag={t}"));
                events.Add(new ParserEvent.ChunkProduced(new ContentChunk(
                    ProtocolVersion: 0, JobId: context.JobId, Sequence: events.Count,
                    VirtualPath: $"{context.VirtualPath}!/manifest.json",
                    FormatId: "docker-archive", ContentKind: ContentKind.Metadata,
                    Encoding: "utf-8", Text: tagText,
                    SourceStart: 0, SourceLength: tagText.Length,
                    LocationMap: Array.Empty<LocationMapEntry>(), IsFinal: false)));
            }

            // Parse config
            string configKey = record.Config ?? "";
            if (tarEntries.TryGetValue(configKey, out var configData))
            {
                OciConfig config;
                try
                {
                    config = OciJsonParser.ParseConfig(configData.Data,
                        $"{context.VirtualPath}!/{configKey}");
                }
                catch (Exception ex)
                {
                    events.Add(new ParserEvent.GapProduced(new CoverageGap(
                        Guid.NewGuid(), context.ScanId, null,
                        $"{context.VirtualPath}!/{configKey}",
                        "docker-archive", "config_parse", GapReason.Corrupt,
                        $"config_parse_error: {ex.Message}", configData.Data.Length, 0,
                        DateTimeOffset.UtcNow)));
                    goto emitConfigMetadata;
                }

                // Emit config-derived chunks
                EmitConfigChunks(config, context, events);

            emitConfigMetadata:;
            }
            else
            {
                events.Add(new ParserEvent.GapProduced(new CoverageGap(
                    Guid.NewGuid(), context.ScanId, null,
                    $"{context.VirtualPath}!/{configKey}",
                    "docker-archive", "config", GapReason.Corrupt,
                    "config_file_missing", null, null, DateTimeOffset.UtcNow)));
            }

            // Parse layers
            int layerIndex = 0;
            if (record.Layers is not null)
            {
                foreach (string layerPath in record.Layers)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (tarEntries.TryGetValue(layerPath.TrimEnd('/'), out var layerData))
                    {
                        string virtualPath = $"{context.VirtualPath}!/{layerPath}";
                        // Emit layer as child-discovered — the orchestrator will route
                        // to OciLayerParser if the probe matches.
                        using var memStream = new MemoryStream(layerData.Data, writable: false);
                        FormatProbe probe;
                        try
                        {
                            probe = await FormatSniffer.ProbeAsync(memStream, ".tar.gz",
                                cancellationToken).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            events.Add(new ParserEvent.GapProduced(new CoverageGap(
                                Guid.NewGuid(), context.ScanId, null, virtualPath,
                                "docker-archive", "sniff", GapReason.Corrupt,
                                $"layer_sniff_failed: {ex.Message}",
                                layerData.Data.Length, 0, DateTimeOffset.UtcNow)));
                            layerIndex++;
                            continue;
                        }

                        byte[] captured = layerData.Data;
                        Func<CancellationToken, Task<Stream>> streamFactory = _ =>
                            Task.FromResult<Stream>(new MemoryStream(captured, writable: false));

                        events.Add(new ParserEvent.ChildDiscovered(
                            virtualPath, probe, streamFactory));
                    }
                    else
                    {
                        events.Add(new ParserEvent.GapProduced(new CoverageGap(
                            Guid.NewGuid(), context.ScanId, null,
                            $"{context.VirtualPath}!/{layerPath}",
                            "docker-archive", "layer", GapReason.Corrupt,
                            "layer_file_missing", null, null, DateTimeOffset.UtcNow)));
                    }

                    layerIndex++;
                }
            }

            recordIndex++;
        }

        events.Add(new ParserEvent.ParseCompleted());
        return events;
    }

    private static void EmitConfigChunks(OciConfig config, ParseContext context, List<ParserEvent> events)
    {
        long seq = events.Count;

        // Architecture/OS
        string platformText = $"architecture={config.Architecture}\nos={config.Os}";
        events.Add(MakeChunk(context, ref seq, config.SourcePath, platformText));

        // Env
        if (config.Env.Count > 0)
        {
            string envText = string.Join("\n", config.Env);
            events.Add(MakeChunk(context, ref seq, config.SourcePath, envText));
        }

        // Labels
        if (config.Labels.Count > 0)
        {
            string labelsText = string.Join("\n",
                config.Labels.Select(kv => $"label={kv.Key}={kv.Value}"));
            events.Add(MakeChunk(context, ref seq, config.SourcePath, labelsText));
        }

        // Entrypoint
        if (!string.IsNullOrEmpty(config.Entrypoint))
        {
            events.Add(MakeChunk(context, ref seq, config.SourcePath,
                $"entrypoint={config.Entrypoint}"));
        }

        // Cmd
        if (!string.IsNullOrEmpty(config.Cmd))
        {
            events.Add(MakeChunk(context, ref seq, config.SourcePath,
                $"cmd={config.Cmd}"));
        }

        // WorkingDir
        if (!string.IsNullOrEmpty(config.WorkingDir))
        {
            events.Add(MakeChunk(context, ref seq, config.SourcePath,
                $"working_dir={config.WorkingDir}"));
        }

        // User
        if (!string.IsNullOrEmpty(config.User))
        {
            events.Add(MakeChunk(context, ref seq, config.SourcePath,
                $"user={config.User}"));
        }

        // ExposedPorts
        if (config.ExposedPorts.Count > 0)
        {
            string portsText = string.Join("\n",
                config.ExposedPorts.Select(p => $"exposed_port={p}"));
            events.Add(MakeChunk(context, ref seq, config.SourcePath, portsText));
        }

        // Volumes
        if (config.Volumes.Count > 0)
        {
            string volumesText = string.Join("\n",
                config.Volumes.Select(v => $"volume={v}"));
            events.Add(MakeChunk(context, ref seq, config.SourcePath, volumesText));
        }

        // Rootfs diff IDs
        if (config.RootfsDiffIds.Count > 0)
        {
            string diffIdsText = string.Join("\n",
                config.RootfsDiffIds.Select(d => $"diff_id={d}"));
            events.Add(MakeChunk(context, ref seq, config.SourcePath, diffIdsText));
        }

        // History
        foreach (var entry in config.History)
        {
            string histText = $"history_created={entry.Created ?? ""}\n"
                + $"history_created_by={entry.CreatedBy ?? ""}\n"
                + $"history_empty_layer={entry.EmptyLayer}";
            if (!string.IsNullOrEmpty(entry.Comment))
                histText += $"\nhistory_comment={entry.Comment}";
            events.Add(MakeChunk(context, ref seq, config.SourcePath, histText));
        }
    }

    private static ParserEvent.ChunkProduced MakeChunk(
        ParseContext context, ref long seq, string virtualPath, string text)
    {
        return new ParserEvent.ChunkProduced(new ContentChunk(
            ProtocolVersion: 0, JobId: context.JobId, Sequence: seq++,
            VirtualPath: virtualPath, FormatId: "docker-archive",
            ContentKind: ContentKind.Metadata, Encoding: "utf-8",
            Text: text, SourceStart: 0, SourceLength: text.Length,
            LocationMap: Array.Empty<LocationMapEntry>(), IsFinal: false));
    }

    private sealed record DockerSaveManifest(
        string Config,
        string[]? RepoTags,
        string[]? Layers);
}
