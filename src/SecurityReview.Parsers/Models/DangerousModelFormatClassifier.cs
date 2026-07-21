using System.Collections.ObjectModel;

namespace SecurityReview.Parsers.Models;

/// <summary>
/// Detects dangerous (potentially executable) model formats — pickle protocols
/// and PyTorch archives — WITHOUT deserializing any objects. Emits file/path/entry
/// names and safe adjacent metadata. Marked NotCovered, task Partial.
/// </summary>
public static class DangerousModelFormatClassifier
{
    // ZIP magic for PyTorch archives (.pt wrappers)
    private static ReadOnlySpan<byte> ZipMagic => [0x50, 0x4B, 0x03, 0x04];

    /// <summary>
    /// Known dangerous model extensions — files that should never be deserialized.
    /// </summary>
    private static readonly HashSet<string> DangerousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pt", ".pth", ".pkl", ".pickle",
    };

    /// <summary>
    /// Safe adjacent file names that provide useful metadata.
    /// </summary>
    public static readonly IReadOnlySet<string> AdjacentMetadataFiles =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "config.json", "tokenizer.json", "tokenizer_config.json",
            "preprocessor_config.json", "generation_config.json",
            "model.safetensors.index.json", "model.safetensors",
        };

    /// <summary>
    /// Classify a byte span. Never invokes deserialization. Returns
    /// classification with detected protocols and entry names.
    /// </summary>
    public static DangerousModelClassification Classify(ReadOnlySpan<byte> data,
        string? extensionHint = null)
    {
        // Check known dangerous extensions
        if (extensionHint != null && DangerousExtensions.Contains(extensionHint))
        {
            var protocols = DetectPickleProtocols(data);
            if (protocols.Count > 0)
                return DangerousModelClassification.Pickle(protocols);
        }

        // Check pickle binary protocols in byte content
        var detectedProtocols = DetectPickleProtocols(data);
        if (detectedProtocols.Count > 0)
            return DangerousModelClassification.Pickle(detectedProtocols);

        // Check for PyTorch archive (ZIP with pickle members)
        if (data.Length >= 4 && data[..4].SequenceEqual(ZipMagic))
        {
            var members = TryListZipMembers(data);
            if (members.Count > 0)
            {
                bool hasPickleMember = members.Any(m =>
                    m.EndsWith(".pkl", StringComparison.OrdinalIgnoreCase) ||
                    m.Contains("data.pkl", StringComparison.OrdinalIgnoreCase));

                if (hasPickleMember)
                {
                    return DangerousModelClassification.PytorchArchive(members, Array.Empty<string>());
                }
            }
        }

        // Check extension hint for zip-wrapped pickle
        if (extensionHint != null &&
            (extensionHint.Equals(".pt", StringComparison.OrdinalIgnoreCase) ||
             extensionHint.Equals(".pth", StringComparison.OrdinalIgnoreCase)))
        {
            // With a .pt extension, even without clear pickle markers,
            // we flag it as suspicious
            return new DangerousModelClassification(
                DangerousModelClass.SuspiciousModel, true,
                Array.Empty<string>(),
                TryListZipMembers(data),
                Array.Empty<string>(),
                "Suspicious model file with dangerous extension — treat as potential pickle, not deserialized");
        }

        // Check for .pkl/.pickle extension — always suspicious even without magic
        if (extensionHint != null &&
            (extensionHint.Equals(".pkl", StringComparison.OrdinalIgnoreCase) ||
             extensionHint.Equals(".pickle", StringComparison.OrdinalIgnoreCase)))
        {
            return DangerousModelClassification.Pickle(Array.Empty<string>());
        }

        return DangerousModelClassification.Safe();
    }

    /// <summary>
    /// Identify safe adjacent files from a directory listing.
    /// </summary>
    public static IReadOnlyList<string> FindSafeAdjacentFiles(IEnumerable<string> siblings)
    {
        return siblings
            .Where(f => AdjacentMetadataFiles.Contains(Path.GetFileName(f)))
            .ToList().AsReadOnly();
    }

    private static ReadOnlyCollection<string> DetectPickleProtocols(ReadOnlySpan<byte> data)
    {
        var protocols = new List<string>();
        if (data.Length >= 2)
        {
            if (data[0] == 0x80 && data[1] == 0x02)
                protocols.Add("protocol_2");
            else if (data[0] == 0x80 && data[1] == 0x03)
                protocols.Add("protocol_3");
            else if (data[0] == 0x80 && data[1] == 0x04)
                protocols.Add("protocol_4");
            else if (data[0] == 0x80 && data[1] == 0x05)
                protocols.Add("protocol_5");
        }

        return protocols.AsReadOnly();
    }

    private static ReadOnlyCollection<string> TryListZipMembers(ReadOnlySpan<byte> data)
    {
        var members = new List<string>();
        try
        {
            if (data.Length < 30) return members.AsReadOnly();

            // Scan for local file headers
            int pos = 0;
            while (pos + 30 <= data.Length)
            {
                if (data[pos] == 0x50 && data[pos + 1] == 0x4B &&
                    data[pos + 2] == 0x03 && data[pos + 3] == 0x04)
                {
                    // Read file name length at offset 26
                    int nameLen = data[pos + 26] | (data[pos + 27] << 8);
                    int extraLen = data[pos + 28] | (data[pos + 29] << 8);

                    if (nameLen > 0 && nameLen < 1024 && pos + 30 + nameLen <= data.Length)
                    {
                        var nameSpan = data.Slice(pos + 30, nameLen);
                        string name = System.Text.Encoding.UTF8.GetString(nameSpan);
                        members.Add(name);
                    }

                    // Skip to next potential header
                    pos += 30 + nameLen + extraLen;
                }
                else
                {
                    pos++;
                }
            }
        }
        catch
        {
            // Non-critical; just return what we found
        }

        return members.AsReadOnly();
    }
}
