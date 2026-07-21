using System.IO.Compression;
using System.Text;
using SecurityReview.RulePack.Normalization;
using SecurityReview.RulePack.Packaging;
using SecurityReview.RulePack.Schema;
using SecurityReview.RulePack.Signing;
using SecurityReview.RulePack.Validation;
using SecurityReview.RulePackBuilder.Excel;

namespace SecurityReview.RulePackBuilder.Commands;

public static class BuildRulePackCommand
{
    public static int Run(
        string inputPath,
        string outputPath,
        string? privateKeyPath = null,
        string? expectedSigner = null)
    {
        ArgumentNullException.ThrowIfNull(inputPath);
        ArgumentNullException.ThrowIfNull(outputPath);

        // Step 1: Open input xlsx and read
        RuleWorkbookReadResult readResult;
        try
        {
            using var stream = File.OpenRead(inputPath);
            readResult = RuleWorkbookReader.Read(stream);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IO Error: Failed to read input workbook: {ex.Message}");
            return 3;
        }

        // Step 2: Check read errors
        if (readResult.Errors.Count > 0)
        {
            foreach (var err in readResult.Errors)
            {
                Console.Error.WriteLine(err.ToString());
            }

            return 1;
        }

        if (readResult.Document is null)
        {
            Console.Error.WriteLine("Validation Error: Workbook produced no document.");
            return 1;
        }

        var document = readResult.Document;
        var packageInfo = readResult.PackageInfo;

        // Step 3: Run RuleGraphValidator.Validate()
        var graphResult = RuleGraphValidator.Validate(document);
        if (!graphResult.IsValid)
        {
            foreach (var err in graphResult.Errors)
            {
                Console.Error.WriteLine(err);
            }

            return 1;
        }

        foreach (var warn in graphResult.Warnings)
        {
            Console.Error.WriteLine($"Warning: {warn}");
        }

        // Step 4: Run RulePackDocument.Validate()
        var docErrors = document.Validate();
        if (docErrors.Count > 0)
        {
            foreach (var err in docErrors)
            {
                Console.Error.WriteLine(err);
            }

            return 1;
        }

        // Step 5: Normalize
        document = RulePackNormalizer.Normalize(document);

        // Step 6: Write package
        string rulePackId = packageInfo.TryGetValue("rulePackId", out var rpid) ? rpid : "default";
        string version = packageInfo.TryGetValue("version", out var ver) ? ver : "1.0.0";
        string minClientVersion = packageInfo.TryGetValue("minClientVersion", out var mcv) ? mcv : "1.0.0";
        string signerKeyId = expectedSigner ?? EcdsaRulePackSigner.DefaultSignerKeyId;
        int schemaVersion = packageInfo.TryGetValue("schemaVersion", out var sv) && int.TryParse(sv, out var svv) ? svv : 1;

        var manifest = RulePackManifest.Create(
            rulePackId: rulePackId,
            version: version,
            minClientVersion: minClientVersion,
            signerKeyId: signerKeyId,
            schemaVersion: schemaVersion,
            files: []);

        byte[] zipBytes;
        try
        {
            zipBytes = RulePackWriter.Write(
                manifest,
                document,
                readResult.Entities,
                readResult.Placeholders,
                readResult.Licenses);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IO Error: Failed to write package: {ex.Message}");
            return 3;
        }

        // Step 7: Sign if private key provided
        if (privateKeyPath is not null)
        {
            try
            {
                zipBytes = SignPackage(zipBytes, privateKeyPath, signerKeyId);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Signature Error: {ex.Message}");
                return 2;
            }
        }

        // Step 8: Write final ZIP to output
        try
        {
            File.WriteAllBytes(outputPath, zipBytes);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IO Error: Failed to write output package: {ex.Message}");
            return 3;
        }

        return 0;
    }

    private static byte[] SignPackage(byte[] zipBytes, string privateKeyPath, string signerKeyId)
    {
        using var privateKey = EcdsaRulePackSigner.LoadPrivateKey(privateKeyPath);

        // Extract manifest.json from ZIP
        byte[] manifestBytes;
        using (var readStream = new MemoryStream(zipBytes))
        using (var archive = new ZipArchive(readStream, ZipArchiveMode.Read))
        {
            var manifestEntry = archive.GetEntry("manifest.json");
            if (manifestEntry is null)
                throw new InvalidOperationException("manifest.json not found in package.");

            using var entryStream = manifestEntry.Open();
            using var ms = new MemoryStream();
            entryStream.CopyTo(ms);
            manifestBytes = ms.ToArray();
        }

        // Sign manifest
        byte[] signature = EcdsaRulePackSigner.SignManifest(manifestBytes, privateKey);

        // Write signature.json
        byte[] signatureJson = EcdsaRulePackSigner.WriteSignatureJson(signature, signerKeyId);

        // Replace signature.json in ZIP
        using (var outputStream = new MemoryStream())
        {
            using (var readStream = new MemoryStream(zipBytes))
            using (var archive = new ZipArchive(readStream, ZipArchiveMode.Read))
            using (var newArchive = new ZipArchive(outputStream, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var entry in archive.Entries)
                {
                    string entryName = entry.FullName.Replace('\\', '/');
                    byte[] content;

                    if (entryName == "signature.json")
                    {
                        content = signatureJson;
                    }
                    else
                    {
                        using var es = entry.Open();
                        using var ms = new MemoryStream();
                        es.CopyTo(ms);
                        content = ms.ToArray();
                    }

                    var newEntry = newArchive.CreateEntry(entryName, CompressionLevel.Optimal);
                    newEntry.LastWriteTime = entry.LastWriteTime;
                    using var newEntryStream = newEntry.Open();
                    newEntryStream.Write(content, 0, content.Length);
                }
            }

            return outputStream.ToArray();
        }
    }
}
